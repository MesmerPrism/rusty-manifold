//! First-slice contract models for Manifold manifests and snapshots.

use core::fmt;

use crate::{DottedId, Revision, SchemaId};

mod command_dispatch;
mod ids;
mod leases;
mod validation_helpers;

pub use self::command_dispatch::*;
use self::ids::*;
pub use self::leases::*;
use self::validation_helpers::*;

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

/// Request to change one module runtime-state snapshot under Manifold authority.
///
/// The request proposes contract state only. It does not start or stop a
/// process, load a module, open a transport, or claim platform lifecycle work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Holder requesting the state transition.
    pub holder_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Lease id proving authority to change this module state.
    pub lease_id: Option<DottedId>,
    /// Capability required for this runtime-state transition.
    pub required_capability: DottedId,
    /// Module whose state is being changed.
    pub module_id: DottedId,
    /// Runtime revision expected before the transition.
    pub from_runtime_revision: Revision,
    /// Proposed accepted module state after the transition.
    pub proposed_state: ManifoldModuleRuntimeState,
}

/// Rejection for a module runtime-state change request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request that was rejected.
    pub request_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe rejection message.
    pub message: String,
    /// Whether retrying after refreshing state may help.
    pub retryable: bool,
    /// Current authority revision observed by the reviewer.
    pub current_authority_revision: Revision,
    /// Current runtime revision for the requested module, if known.
    pub current_runtime_revision: Option<Revision>,
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
                    rejected_id: stream.source_module_id.clone(),
                    kind: StreamRegistryValidationErrorKind::UnknownModuleLink,
                });
            }
        }

        Ok(())
    }

    /// Validates that endpoint-bound transport offers reference known endpoint ids.
    ///
    /// # Errors
    ///
    /// Returns [`StreamRegistryValidationError`] when a stream transport offer
    /// points at an endpoint that the selected host does not advertise.
    pub fn validate_transport_endpoints(
        &self,
        endpoint_ids: &[DottedId],
    ) -> Result<(), StreamRegistryValidationError> {
        for stream in &self.streams {
            for offer in &stream.transport_offers {
                if let Some(endpoint_id) = &offer.endpoint_id {
                    if !endpoint_ids.iter().any(|known| known == endpoint_id) {
                        return Err(StreamRegistryValidationError {
                            stream_id: stream.stream_id.clone(),
                            rejected_id: endpoint_id.clone(),
                            kind: StreamRegistryValidationErrorKind::UnknownTransportEndpoint,
                        });
                    }
                }
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

/// Request to change the accepted stream registry.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Holder id.
    pub holder_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Lease id authorizing registry mutation.
    pub lease_id: Option<DottedId>,
    /// Capability required for the registry change.
    pub required_capability: DottedId,
    /// Proposed registry diff.
    pub diff: ManifoldStreamRegistryDiff,
}

/// Rejected stream-registry change result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryRejection {
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
    /// Current authority revision.
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision.
    pub current_registry_revision: Revision,
}

/// Request to subscribe to one accepted stream transport offer.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Subscriber id.
    pub subscriber_id: DottedId,
    /// Subscriber class used for manifest policy checks.
    pub subscriber_kind: ManifoldStreamSubscriberKind,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Expected stream-registry revision.
    pub expected_registry_revision: Revision,
    /// Stream to subscribe to.
    pub stream_id: DottedId,
    /// Transport offer selected by the subscriber.
    pub transport_id: DottedId,
    /// Requested time-to-live in milliseconds.
    pub requested_ttl_ms: u64,
    /// Capability required to admit this subscription.
    pub required_capability: DottedId,
    /// Request timestamp in milliseconds in the subscriber's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Accepted stream subscription.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscription {
    /// Schema identifier for this subscription.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable subscription id.
    pub subscription_id: DottedId,
    /// Request id that created this subscription.
    pub request_id: DottedId,
    /// Subscriber id.
    pub subscriber_id: DottedId,
    /// Subscriber class admitted by policy.
    pub subscriber_kind: ManifoldStreamSubscriberKind,
    /// Stream being subscribed to.
    pub stream_id: DottedId,
    /// Transport offer selected for the subscription.
    pub transport_id: DottedId,
    /// Endpoint used by the transport offer, when endpoint-bound.
    pub endpoint_id: Option<DottedId>,
    /// Subscription state.
    pub state: ManifoldStreamSubscriptionState,
    /// Authority revision at which the subscription was accepted.
    pub accepted_authority_revision: Revision,
    /// Registry revision at which the stream offer was accepted.
    pub accepted_registry_revision: Revision,
    /// Acceptance timestamp in milliseconds.
    pub accepted_at_ms: u64,
    /// Expiration timestamp in milliseconds.
    pub expires_at_ms: u64,
    /// Capability used to admit the subscription.
    pub required_capability: DottedId,
}

/// Rejected stream subscription request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRejection {
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
    /// Current authority revision.
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision.
    pub current_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
}

/// Request to release one accepted active stream subscription.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Subscription to release.
    pub subscription_id: DottedId,
    /// Subscriber id expected to own the subscription.
    pub subscriber_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Expected stream-registry revision.
    pub expected_registry_revision: Revision,
    /// Stream expected to own the subscription.
    pub stream_id: DottedId,
    /// Machine-readable reason for releasing the subscription.
    pub release_reason: DottedId,
    /// Request timestamp in milliseconds in the subscriber's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected stream subscription release request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseRejection {
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
    /// Current authority revision.
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision.
    pub current_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
}

/// Request to renew one accepted active stream subscription.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id.
    pub request_id: DottedId,
    /// Subscription to renew.
    pub subscription_id: DottedId,
    /// Subscriber id expected to own the subscription.
    pub subscriber_id: DottedId,
    /// Expected authority revision.
    pub expected_authority_revision: Revision,
    /// Expected stream-registry revision.
    pub expected_registry_revision: Revision,
    /// Stream expected to own the subscription.
    pub stream_id: DottedId,
    /// Transport offer expected by the subscriber.
    pub transport_id: DottedId,
    /// Requested subscription duration from the review clock wall time.
    pub requested_ttl_ms: u64,
    /// Machine-readable reason for renewing the subscription.
    pub renewal_reason: DottedId,
    /// Request timestamp in milliseconds in the subscriber's chosen clock domain.
    pub requested_at_ms: u64,
}

/// Rejected stream subscription renewal request result.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalRejection {
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
    /// Current authority revision.
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision.
    pub current_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
    /// Current expiration, when the referenced active subscription was known.
    pub current_expires_at_ms: Option<u64>,
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

/// Request to sweep expired accepted authority state.
///
/// The request is source-only authority maintenance. It asks Manifold to
/// classify active leases and active stream subscriptions by the supplied
/// review clock and prepare an auditable accepted-state transition; it does
/// not start timers, close transports, notify holders, or contact runtimes.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Actor requesting the sweep.
    pub requester_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Stream-registry revision the requester observed.
    pub expected_registry_revision: Revision,
    /// Machine-readable reason for the sweep.
    pub sweep_reason: DottedId,
    /// Request timestamp in milliseconds in the requester clock domain.
    pub requested_at_ms: u64,
}

/// Rejection for an authority expiry sweep request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request id being rejected.
    pub request_id: DottedId,
    /// Machine-readable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe explanation.
    pub message: String,
    /// Whether retrying after refreshing state or time may help.
    pub retryable: bool,
    /// Current authority revision observed by the reviewer.
    pub current_authority_revision: Revision,
    /// Current accepted stream-registry revision observed by the reviewer.
    pub current_registry_revision: Revision,
    /// Expired active lease count at the review clock.
    pub expired_lease_count: usize,
    /// Expired active stream subscription count at the review clock.
    pub expired_subscription_count: usize,
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

/// Request to change the accepted host manifest under Manifold authority.
///
/// The request proposes contract state only. It does not start host services,
/// open endpoints, probe platform permissions, or execute adapter code.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Holder requesting the host manifest change.
    pub holder_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Lease id proving authority to change the host manifest.
    pub lease_id: Option<DottedId>,
    /// Capability required for host manifest mutation.
    pub required_capability: DottedId,
    /// Proposed accepted host manifest after the change.
    pub proposed_manifest: ManifoldHostManifest,
}

/// Rejection for a host manifest change request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request that was rejected.
    pub request_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe rejection message.
    pub message: String,
    /// Whether retrying after refreshing state may help.
    pub retryable: bool,
    /// Current authority revision observed by the reviewer.
    pub current_authority_revision: Revision,
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

/// Request to change the accepted clock snapshot under Manifold authority.
///
/// The request proposes contract state only. It does not read a live clock,
/// change OS time, start a clock service, or open any host adapter.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotChangeRequest {
    /// Schema identifier for this request.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable request id.
    pub request_id: DottedId,
    /// Holder requesting the clock snapshot change.
    pub holder_id: DottedId,
    /// Authority revision the requester observed.
    pub expected_authority_revision: Revision,
    /// Lease id proving authority to change the clock snapshot.
    pub lease_id: Option<DottedId>,
    /// Capability required for clock mutation.
    pub required_capability: DottedId,
    /// Clock epoch id the requester observed before the proposed change.
    pub from_clock_epoch_id: DottedId,
    /// Clock sequence the requester observed before the proposed change.
    pub from_clock_sequence: u64,
    /// Proposed accepted clock snapshot after the change.
    pub proposed_snapshot: ManifoldClockSnapshot,
}

/// Rejection for a clock snapshot change request.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Request that was rejected.
    pub request_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe rejection message.
    pub message: String,
    /// Whether retrying after refreshing state may help.
    pub retryable: bool,
    /// Current authority revision observed by the reviewer.
    pub current_authority_revision: Revision,
    /// Current clock epoch id observed by the reviewer.
    pub current_clock_epoch_id: DottedId,
    /// Current clock sequence observed by the reviewer.
    pub current_clock_sequence: u64,
}

/// Snapshot of the Manifold state used to review command authority.
///
/// This is a data contract only. It records the authority inputs a validator,
/// GUI, CLI, or host shell can inspect before issuing or auditing a mutating
/// command; it does not imply sockets, runtime loading, or platform adapters.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthoritySnapshot {
    /// Schema identifier for this snapshot.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable authority id.
    pub authority_id: DottedId,
    /// Authority revision used for command and lease preconditions.
    pub authority_revision: Revision,
    /// Host manifest that owns this authority view.
    pub host_manifest: ManifoldHostManifest,
    /// Clock snapshot used for authority decisions.
    pub clock_snapshot: ManifoldClockSnapshot,
    /// Stream registry visible to command routing.
    pub stream_registry: ManifoldStreamRegistrySnapshot,
    /// Module runtime states visible to the authority.
    pub module_runtime_states: Vec<ManifoldModuleRuntimeState>,
    /// Command ids advertised through package or runtime contracts.
    pub command_ids: Vec<DottedId>,
    /// Descriptors for commands the authority can fully validate.
    pub command_descriptors: Vec<ManifoldCommandDescriptor>,
    /// Active control leases considered by the authority.
    pub active_leases: Vec<ManifoldControlLease>,
    /// Active stream subscriptions admitted by the authority.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub active_stream_subscriptions: Vec<ManifoldStreamSubscription>,
}

impl ManifoldAuthoritySnapshot {
    /// Validates that command, lease, stream, module, host, and clock inputs align.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when any authority input
    /// points outside the snapshot or advertises an unsafe host/clock/lease pairing.
    pub fn validate_authority_links(&self) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.snapshot.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.authority_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.host_manifest.authority_role == AuthorityRole::None {
            return Err(ManifoldAuthorityValidationError::new(
                self.authority_id.clone(),
                self.host_manifest.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostHasNoAuthority,
            ));
        }

        if let Err(error) = self.host_manifest.validate_endpoint_security() {
            return Err(ManifoldAuthorityValidationError::new(
                self.authority_id.clone(),
                error.endpoint_id().to_string(),
                ManifoldAuthorityValidationErrorKind::HostEndpointSecurityMismatch,
            ));
        }

        if self.host_manifest.clock_domain != self.clock_snapshot.clock_domain {
            return Err(ManifoldAuthorityValidationError::new(
                self.authority_id.clone(),
                self.clock_snapshot.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockDomainMismatch,
            ));
        }

        if self.stream_registry.registry_revision > self.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.authority_id.clone(),
                self.stream_registry.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionAhead,
            ));
        }

        let module_ids = self
            .module_runtime_states
            .iter()
            .map(|state| state.module_id.clone())
            .collect::<Vec<_>>();
        for stream in &self.stream_registry.streams {
            if !module_ids
                .iter()
                .any(|module_id| module_id == &stream.source_module_id)
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    stream.source_module_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownStreamModule,
                ));
            }
        }

        let stream_ids = self
            .stream_registry
            .streams
            .iter()
            .map(|stream| stream.stream_id.clone())
            .collect::<Vec<_>>();
        for state in &self.module_runtime_states {
            for stream_id in &state.active_streams {
                if !stream_ids.iter().any(|known| known == stream_id) {
                    return Err(ManifoldAuthorityValidationError::new(
                        state.module_id.clone(),
                        stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownModuleStream,
                    ));
                }
            }

            for command_id in &state.active_commands {
                if !self.command_ids.iter().any(|known| known == command_id) {
                    return Err(ManifoldAuthorityValidationError::new(
                        state.module_id.clone(),
                        command_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownModuleCommand,
                    ));
                }
            }
        }

        for descriptor in &self.command_descriptors {
            if !self
                .command_ids
                .iter()
                .any(|command_id| command_id == &descriptor.command_id)
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    descriptor.command_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownCommand,
                ));
            }

            if !self
                .host_manifest
                .capabilities
                .iter()
                .any(|capability| capability == &descriptor.required_capability)
            {
                return Err(ManifoldAuthorityValidationError::new(
                    descriptor.command_id.clone(),
                    descriptor.required_capability.to_string(),
                    ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised,
                ));
            }
        }

        for lease in &self.active_leases {
            if lease.state != LeaseState::Active {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::InactiveLease,
                ));
            }

            if lease.granted_revision > self.authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead,
                ));
            }

            if !self
                .host_manifest
                .capabilities
                .iter()
                .any(|capability| capability == &lease.required_capability)
            {
                return Err(ManifoldAuthorityValidationError::new(
                    lease.lease_id.clone(),
                    lease.required_capability.to_string(),
                    ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised,
                ));
            }
        }

        if let Some(subscription_id) = duplicate_subscription_id(&self.active_stream_subscriptions)
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.authority_id.clone(),
                subscription_id.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        let endpoint_ids = self
            .host_manifest
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint_id.clone())
            .collect::<Vec<_>>();
        for subscription in &self.active_stream_subscriptions {
            if subscription.state != ManifoldStreamSubscriptionState::Active {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    subscription.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }

            if subscription.accepted_authority_revision > self.authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    subscription.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
                ));
            }

            if subscription.accepted_registry_revision > self.stream_registry.registry_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.authority_id.clone(),
                    subscription.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
                ));
            }

            if !self
                .host_manifest
                .capabilities
                .iter()
                .any(|capability| capability == &subscription.required_capability)
            {
                return Err(ManifoldAuthorityValidationError::new(
                    subscription.subscription_id.clone(),
                    subscription.required_capability.to_string(),
                    ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised,
                ));
            }

            let stream = self
                .stream_manifest(&subscription.stream_id)
                .ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.authority_id.clone(),
                        subscription.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownStream,
                    )
                })?;

            let offer = stream
                .transport_offers
                .iter()
                .find(|offer| offer.transport_id == subscription.transport_id)
                .ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.authority_id.clone(),
                        subscription.transport_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownTransport,
                    )
                })?;

            if offer.endpoint_id != subscription.endpoint_id {
                return Err(ManifoldAuthorityValidationError::new(
                    subscription.subscription_id.clone(),
                    subscription.transport_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }

            if let Some(endpoint_id) = &subscription.endpoint_id {
                if !endpoint_ids.iter().any(|known| known == endpoint_id) {
                    return Err(ManifoldAuthorityValidationError::new(
                        subscription.subscription_id.clone(),
                        endpoint_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownTransport,
                    ));
                }
            }

            if subscription.subscriber_kind == ManifoldStreamSubscriberKind::Ui
                && !stream.subscription.ui_subscribable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    subscription.subscription_id.clone(),
                    subscription.stream_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionNotAllowed,
                ));
            }
        }

        for stream in &self.stream_registry.streams {
            if let Some(max_subscribers) = stream.subscription.max_subscribers {
                let active_count = self.active_subscription_count(&stream.stream_id);
                if active_count > max_subscribers {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.authority_id.clone(),
                        stream.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionLimitReached,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Deterministically reviews one command envelope against this authority snapshot.
    ///
    /// The review is source-only: it does not execute the command, mutate runtime
    /// state, open transports, or contact a host. Accepted reviews advance the
    /// reported authority revision by one; rejected reviews keep the current
    /// authority revision in the rejection.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_command(
        &self,
        envelope: ManifoldCommandEnvelope,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldCommandAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                envelope.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                envelope.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.command_authority_decision(&envelope, &recorded_clock);
        let lease = envelope
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            CommandAuthorityDecision::Accepted => {
                let accepted_revision = self.authority_revision.next().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        envelope.request_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    )
                })?;
                (
                    ManifoldCommandAuthorityReviewOutcome::CommandAccepted,
                    Some(ManifoldCommandAck {
                        schema_id: command_ack_schema_id(),
                        request_id: envelope.request_id.clone(),
                        accepted_revision,
                        lease_id: envelope.lease_id.clone(),
                        authority_id: self.authority_id.clone(),
                        accepted_at_ms: wall_unix_ms_u64(&recorded_clock),
                    }),
                    None,
                )
            }
            CommandAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldCommandAuthorityReviewOutcome::CommandRejected,
                None,
                Some(ManifoldCommandRejection {
                    schema_id: command_rejection_schema_id(),
                    request_id: envelope.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code literal is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: Some(self.authority_revision),
                }),
            ),
        };

        let audit_event = ManifoldCommandAuthorityAuditEvent {
            schema_id: command_authority_audit_event_schema_id(),
            event_id: command_authority_audit_event_id(&envelope.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            event_kind: outcome.into(),
            envelope,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldCommandAuthorityReview {
            schema_id: command_authority_review_schema_id(),
            review_id: command_authority_review_id(&audit_event.envelope.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Prepares one accepted command review for downstream dispatch.
    ///
    /// The receipt is source-only. It confirms that a command authority review
    /// is valid for this snapshot and is ready for a downstream transport or
    /// executor to consume, but it does not execute the command, mutate
    /// accepted authority state, open transports, or contact a host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this snapshot is
    /// invalid or the supplied review does not match this authority snapshot.
    pub fn prepare_command_dispatch(
        &self,
        review: ManifoldCommandAuthorityReview,
    ) -> Result<ManifoldCommandDispatchReceipt, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;
        review.validate_against_snapshot(self)?;

        let dispatch_id = command_dispatch_receipt_id(&review.review_id);
        let command_id = review.audit_event.envelope.command_id.clone();
        let request_id = review.audit_event.envelope.request_id.clone();

        let (outcome, ack, rejection) =
            if review.outcome == ManifoldCommandAuthorityReviewOutcome::CommandRejected {
                (
                    ManifoldCommandDispatchReceiptOutcome::CommandDispatchRejected,
                    None,
                    Some(ManifoldCommandDispatchRejection {
                        schema_id: command_dispatch_rejection_schema_id(),
                        dispatch_id: dispatch_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "command review did not accept a command".to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            } else {
                let ack = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                (
                    ManifoldCommandDispatchReceiptOutcome::CommandDispatchReady,
                    Some(ack),
                    None,
                )
            };

        let receipt = ManifoldCommandDispatchReceipt {
            schema_id: command_dispatch_receipt_schema_id(),
            dispatch_id,
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            command_id,
            request_id,
            outcome,
            ack,
            rejection,
            review,
        };
        receipt.validate_against_snapshot(self)?;
        Ok(receipt)
    }

    /// Deterministically reviews one control lease request against this authority snapshot.
    ///
    /// The review is source-only: it does not mutate the accepted lease set,
    /// renew leases, execute commands, or contact a host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_lease_request(
        &self,
        request: ManifoldControlLeaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.lease_authority_decision(&request);
        let (outcome, accepted, rejection) = match decision {
            LeaseAuthorityDecision::Accepted => (
                ManifoldControlLeaseAuthorityReviewOutcome::LeaseAccepted,
                Some(ManifoldControlLease {
                    schema_id: control_lease_schema_id(),
                    lease_id: control_lease_id(&request.request_id),
                    holder_id: request.holder_id.clone(),
                    scope: request.scope.clone(),
                    state: LeaseState::Active,
                    granted_revision: self.authority_revision,
                    expires_at_ms: wall_unix_ms_u64(&recorded_clock)
                        .saturating_add(request.requested_ttl_ms),
                    required_capability: request.required_capability.clone(),
                }),
                None,
            ),
            LeaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                conflicting_lease_id,
            } => (
                ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected,
                None,
                Some(ManifoldControlLeaseRejection {
                    schema_id: control_lease_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code literal is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: self.authority_revision,
                    conflicting_lease_id,
                }),
            ),
        };

        let audit_event = ManifoldControlLeaseAuthorityAuditEvent {
            schema_id: control_lease_authority_audit_event_schema_id(),
            event_id: control_lease_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldControlLeaseAuthorityReview {
            schema_id: control_lease_authority_review_schema_id(),
            review_id: control_lease_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one control-lease authority review to this snapshot.
    ///
    /// Accepted lease reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the accepted active lease
    /// appended. Rejected reviews produce a machine-readable application
    /// rejection and leave accepted state unchanged. This is source-only: it
    /// does not renew leases, execute commands, mutate runtime state, open
    /// transports, or contact a host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_control_lease_authority_review(
        &self,
        review: ManifoldControlLeaseAuthorityReview,
    ) -> Result<ManifoldControlLeaseAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = control_lease_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let request_id = review.audit_event.request.request_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "control lease review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome == ManifoldControlLeaseAuthorityReviewOutcome::LeaseRejected =>
            {
                (
                    ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "control lease review did not accept a lease".to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let accepted_lease = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot.active_leases.push(accepted_lease);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldControlLeaseAuthorityApplication {
            schema_id: control_lease_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            request_id,
            lease_scope,
            from_active_lease_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one active control lease release request.
    ///
    /// The review is source-only: it verifies release preconditions against
    /// accepted authority state and records the lease to remove, but it does
    /// not cancel timers, execute commands, contact hosts, or notify runtimes.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_control_lease_release(
        &self,
        request: ManifoldControlLeaseReleaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseReleaseAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.lease_release_authority_decision(&request, &recorded_clock);
        let active_lease_count = self.active_leases.len();
        let (outcome, released, rejection) = match decision {
            LeaseReleaseAuthorityDecision::Released(lease) => (
                ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased,
                Some(lease),
                None,
            ),
            LeaseReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
            } => (
                ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected,
                None,
                Some(ManifoldControlLeaseReleaseRejection {
                    schema_id: control_lease_release_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: self.authority_revision,
                    active_lease_count,
                }),
            ),
        };

        let audit_event = ManifoldControlLeaseReleaseAuthorityAuditEvent {
            schema_id: control_lease_release_authority_audit_event_schema_id(),
            event_id: control_lease_release_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            active_lease_count,
            event_kind: outcome.into(),
            request,
            released: released.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldControlLeaseReleaseAuthorityReview {
            schema_id: control_lease_release_authority_review_schema_id(),
            review_id: control_lease_release_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            released,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one control lease release authority review.
    ///
    /// Accepted release reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the released lease removed
    /// from the active set. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_control_lease_release_authority_review(
        &self,
        review: ManifoldControlLeaseReleaseAuthorityReview,
    ) -> Result<ManifoldControlLeaseReleaseAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = control_lease_release_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let lease_id = review.audit_event.request.lease_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "control lease release review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected =>
            {
                (
                    ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "control lease release review did not release a lease".to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let released_lease = review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) = next_snapshot
                    .active_leases
                    .iter()
                    .position(|lease| lease.lease_id == released_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        released_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                next_snapshot.active_leases.remove(position);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldControlLeaseReleaseAuthorityApplication {
            schema_id: control_lease_release_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            lease_id,
            lease_scope,
            from_active_lease_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one active control lease renewal request.
    ///
    /// The review is source-only: it verifies renewal preconditions against
    /// accepted active lease state and produces a renewed lease candidate or
    /// machine-readable rejection. It does not start timers, execute commands,
    /// contact a host, or mutate accepted authority state.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_control_lease_renewal(
        &self,
        request: ManifoldControlLeaseRenewalRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldControlLeaseRenewalAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let active_lease_count = self.active_leases.len();
        let decision = self.lease_renewal_authority_decision(&request, &recorded_clock);
        let (outcome, renewed, rejection) = match decision {
            LeaseRenewalAuthorityDecision::Renewed(lease) => (
                ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed,
                Some(lease),
                None,
            ),
            LeaseRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
                current_expires_at_ms,
            } => (
                ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected,
                None,
                Some(ManifoldControlLeaseRenewalRejection {
                    schema_id: control_lease_renewal_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_revision: self.authority_revision,
                    active_lease_count,
                    current_expires_at_ms,
                }),
            ),
        };

        let audit_event = ManifoldControlLeaseRenewalAuthorityAuditEvent {
            schema_id: control_lease_renewal_authority_audit_event_schema_id(),
            event_id: control_lease_renewal_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            active_lease_count,
            event_kind: outcome.into(),
            request,
            renewed: renewed.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldControlLeaseRenewalAuthorityReview {
            schema_id: control_lease_renewal_authority_review_schema_id(),
            review_id: control_lease_renewal_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            outcome,
            renewed,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one control lease renewal authority review.
    ///
    /// Accepted renewal reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the reviewed lease replaced
    /// by its renewed candidate. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_control_lease_renewal_authority_review(
        &self,
        review: ManifoldControlLeaseRenewalAuthorityReview,
    ) -> Result<ManifoldControlLeaseRenewalAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = control_lease_renewal_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let lease_id = review.audit_event.request.lease_id.clone();
        let lease_scope = review.audit_event.request.scope.clone();
        let from_active_lease_count = self.active_leases.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "control lease renewal review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected =>
            {
                (
                    ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "control lease renewal review did not renew a lease".to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let renewed_lease = review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) = next_snapshot
                    .active_leases
                    .iter()
                    .position(|lease| lease.lease_id == renewed_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        renewed_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                next_snapshot.active_leases[position] = renewed_lease;
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldControlLeaseRenewalAuthorityApplication {
            schema_id: control_lease_renewal_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            lease_id,
            lease_scope,
            from_active_lease_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one authority expiry sweep request.
    ///
    /// The review is source-only: it classifies accepted active leases and
    /// active stream subscriptions as expired at the supplied review clock and
    /// records exactly which accepted-state entries should be removed. It does
    /// not start timers, execute commands, close transports, contact hosts, or
    /// notify holders/subscribers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_authority_expiry_sweep(
        &self,
        request: ManifoldAuthorityExpirySweepRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldAuthorityExpirySweepAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.authority_expiry_sweep_decision(&request, &recorded_clock);
        let (outcome, expired_leases, expired_stream_subscriptions, rejection) = match decision {
            AuthorityExpirySweepDecision::Accepted {
                expired_leases,
                expired_stream_subscriptions,
            } => (
                ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted,
                expired_leases,
                expired_stream_subscriptions,
                None,
            ),
            AuthorityExpirySweepDecision::Rejected {
                rejection_code,
                message,
                retryable,
                expired_lease_count,
                expired_subscription_count,
            } => (
                ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected,
                Vec::new(),
                Vec::new(),
                Some(ManifoldAuthorityExpirySweepRejection {
                    schema_id: authority_expiry_sweep_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    expired_lease_count,
                    expired_subscription_count,
                }),
            ),
        };

        let audit_event = ManifoldAuthorityExpirySweepAuthorityAuditEvent {
            schema_id: authority_expiry_sweep_authority_audit_event_schema_id(),
            event_id: authority_expiry_sweep_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            event_kind: outcome.into(),
            request,
            expired_leases: expired_leases.clone(),
            expired_stream_subscriptions: expired_stream_subscriptions.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldAuthorityExpirySweepAuthorityReview {
            schema_id: authority_expiry_sweep_authority_review_schema_id(),
            review_id: authority_expiry_sweep_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            expired_leases,
            expired_stream_subscriptions,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one authority expiry sweep review.
    ///
    /// Accepted sweep reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and exactly the reviewed expired
    /// leases/subscriptions removed from accepted state. Rejected reviews
    /// produce a machine-readable application rejection and leave accepted
    /// state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_authority_expiry_sweep_review(
        &self,
        review: ManifoldAuthorityExpirySweepAuthorityReview,
    ) -> Result<ManifoldAuthorityExpirySweepAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = authority_expiry_sweep_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let from_active_lease_count = self.active_leases.len();
        let from_active_subscription_count = self.active_stream_subscriptions.len();

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpirySweepApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "authority expiry sweep review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected =>
            {
                (
                    ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpirySweepApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "authority expiry sweep review did not accept expired state"
                            .to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };

                let expired_lease_ids = review
                    .expired_leases
                    .iter()
                    .map(|lease| lease.lease_id.clone())
                    .collect::<Vec<_>>();
                let expired_subscription_ids = review
                    .expired_stream_subscriptions
                    .iter()
                    .map(|subscription| subscription.subscription_id.clone())
                    .collect::<Vec<_>>();

                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot
                    .active_leases
                    .retain(|lease| !expired_lease_ids.iter().any(|id| id == &lease.lease_id));
                next_snapshot
                    .active_stream_subscriptions
                    .retain(|subscription| {
                        !expired_subscription_ids
                            .iter()
                            .any(|id| id == &subscription.subscription_id)
                    });
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldAuthorityExpirySweepAuthorityApplication {
            schema_id: authority_expiry_sweep_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            request_id: review.audit_event.request.request_id.clone(),
            from_active_lease_count,
            from_active_subscription_count,
            expired_lease_count: review.expired_leases.len(),
            expired_subscription_count: review.expired_stream_subscriptions.len(),
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one stream-registry change request against this authority snapshot.
    ///
    /// The review is source-only: it applies the proposed diff to contract data
    /// only and does not publish streams, open transports, start modules, or
    /// mutate a runtime registry.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_registry_change(
        &self,
        request: ManifoldStreamRegistryChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamRegistryAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.stream_registry_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            StreamRegistryAuthorityDecision::Accepted(snapshot) => (
                ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted,
                Some(snapshot),
                None,
            ),
            StreamRegistryAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected,
                None,
                Some(ManifoldStreamRegistryRejection {
                    schema_id: stream_registry_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                }),
            ),
        };

        let audit_event = ManifoldStreamRegistryAuthorityAuditEvent {
            schema_id: stream_registry_authority_audit_event_schema_id(),
            event_id: stream_registry_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamRegistryAuthorityReview {
            schema_id: stream_registry_authority_review_schema_id(),
            review_id: stream_registry_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream-registry authority review to this snapshot.
    ///
    /// Accepted registry reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the accepted stream registry
    /// installed. Rejected reviews produce a machine-readable application
    /// rejection and leave accepted state unchanged. This is source-only: it
    /// does not publish streams, open transports, notify subscribers, or
    /// mutate a runtime registry.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_registry_authority_review(
        &self,
        review: ManifoldStreamRegistryAuthorityReview,
    ) -> Result<ManifoldStreamRegistryAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = stream_registry_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream registry review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected =>
            {
                (
                    ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream registry review did not accept a registry snapshot"
                            .to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot.stream_registry = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamRegistryAuthorityApplicationOutcome::RegistrySnapshotApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamRegistryAuthorityApplication {
            schema_id: stream_registry_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one stream subscription request.
    ///
    /// The review is source-only: it admits or rejects a subscriber against the
    /// accepted stream manifest and host capability state, but it does not open
    /// transports, notify subscribers, or contact runtime providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_subscription(
        &self,
        request: ManifoldStreamSubscriptionRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamSubscriptionAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.stream_subscription_authority_decision(&request, &recorded_clock);
        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let (outcome, accepted, rejection) = match decision {
            StreamSubscriptionAuthorityDecision::Accepted(subscription) => (
                ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted,
                Some(subscription),
                None,
            ),
            StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
            } => (
                ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected,
                None,
                Some(ManifoldStreamSubscriptionRejection {
                    schema_id: stream_subscription_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    active_subscriber_count,
                }),
            ),
        };

        let audit_event = ManifoldStreamSubscriptionAuthorityAuditEvent {
            schema_id: stream_subscription_authority_audit_event_schema_id(),
            event_id: stream_subscription_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            active_subscriber_count,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamSubscriptionAuthorityReview {
            schema_id: stream_subscription_authority_review_schema_id(),
            review_id: stream_subscription_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream subscription authority review.
    ///
    /// Accepted subscription reviews produce a new `ManifoldAuthoritySnapshot`
    /// with the authority revision advanced by one and the accepted active
    /// subscription appended. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged. This is
    /// source-only: it does not open transports, notify subscribers, or contact
    /// runtime providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_subscription_authority_review(
        &self,
        review: ManifoldStreamSubscriptionAuthorityReview,
    ) -> Result<ManifoldStreamSubscriptionAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = stream_subscription_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let stream_id = review.audit_event.request.stream_id.clone();
        let from_active_subscriber_count = self.active_subscription_count(&stream_id);

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream subscription review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected =>
            {
                (
                    ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream subscription review did not accept a subscription"
                            .to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let accepted_subscription = review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                next_snapshot
                    .active_stream_subscriptions
                    .push(accepted_subscription);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamSubscriptionAuthorityApplication {
            schema_id: stream_subscription_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            stream_id,
            from_active_subscriber_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one active stream subscription release request.
    ///
    /// The review is source-only: it verifies the release preconditions against
    /// accepted authority state and records the subscription to remove, but it
    /// does not close transports, notify subscribers, or contact providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_subscription_release(
        &self,
        request: ManifoldStreamSubscriptionReleaseRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamSubscriptionReleaseAuthorityReview, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision =
            self.stream_subscription_release_authority_decision(&request, &recorded_clock);
        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let (outcome, released, rejection) = match decision {
            StreamSubscriptionReleaseAuthorityDecision::Released(subscription) => (
                ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased,
                Some(subscription),
                None,
            ),
            StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
            } => (
                ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected,
                None,
                Some(ManifoldStreamSubscriptionReleaseRejection {
                    schema_id: stream_subscription_release_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    active_subscriber_count,
                }),
            ),
        };

        let audit_event = ManifoldStreamSubscriptionReleaseAuthorityAuditEvent {
            schema_id: stream_subscription_release_authority_audit_event_schema_id(),
            event_id: stream_subscription_release_authority_audit_event_id(
                &request.request_id,
                outcome,
            ),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            active_subscriber_count,
            event_kind: outcome.into(),
            request,
            released: released.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamSubscriptionReleaseAuthorityReview {
            schema_id: stream_subscription_release_authority_review_schema_id(),
            review_id: stream_subscription_release_authority_review_id(
                &audit_event.request.request_id,
            ),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            released,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream subscription release authority review.
    ///
    /// Accepted release reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the released subscription
    /// removed from the active set. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_subscription_release_authority_review(
        &self,
        review: ManifoldStreamSubscriptionReleaseAuthorityReview,
    ) -> Result<
        ManifoldStreamSubscriptionReleaseAuthorityApplication,
        ManifoldAuthorityValidationError,
    > {
        self.validate_authority_links()?;

        let application_id =
            stream_subscription_release_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let stream_id = review.audit_event.request.stream_id.clone();
        let subscription_id = review.audit_event.request.subscription_id.clone();
        let from_active_subscriber_count = self.active_subscription_count(&stream_id);

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream subscription release review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected =>
            {
                (
                    ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream subscription release review did not release a subscription"
                            .to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let released_subscription = review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) = next_snapshot
                    .active_stream_subscriptions
                    .iter()
                    .position(|subscription| {
                        subscription.subscription_id == released_subscription.subscription_id
                    })
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        released_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                next_snapshot.active_stream_subscriptions.remove(position);
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamSubscriptionReleaseAuthorityApplication {
            schema_id: stream_subscription_release_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            stream_id,
            subscription_id,
            from_active_subscriber_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one active stream subscription renewal request.
    ///
    /// The review is source-only: it verifies renewal preconditions against
    /// accepted authority state and records the renewed subscription, but it
    /// does not open transports, notify subscribers, or contact providers.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_stream_subscription_renewal(
        &self,
        request: ManifoldStreamSubscriptionRenewalRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldStreamSubscriptionRenewalAuthorityReview, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision =
            self.stream_subscription_renewal_authority_decision(&request, &recorded_clock);
        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let (outcome, renewed, rejection) = match decision {
            StreamSubscriptionRenewalAuthorityDecision::Renewed(subscription) => (
                ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed,
                Some(subscription),
                None,
            ),
            StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
                current_expires_at_ms,
            } => (
                ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected,
                None,
                Some(ManifoldStreamSubscriptionRenewalRejection {
                    schema_id: stream_subscription_renewal_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_registry_revision: self.stream_registry.registry_revision,
                    active_subscriber_count,
                    current_expires_at_ms,
                }),
            ),
        };

        let audit_event = ManifoldStreamSubscriptionRenewalAuthorityAuditEvent {
            schema_id: stream_subscription_renewal_authority_audit_event_schema_id(),
            event_id: stream_subscription_renewal_authority_audit_event_id(
                &request.request_id,
                outcome,
            ),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_registry_revision: self.stream_registry.registry_revision,
            active_subscriber_count,
            event_kind: outcome.into(),
            request,
            renewed: renewed.clone(),
            rejection: rejection.clone(),
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldStreamSubscriptionRenewalAuthorityReview {
            schema_id: stream_subscription_renewal_authority_review_schema_id(),
            review_id: stream_subscription_renewal_authority_review_id(
                &audit_event.request.request_id,
            ),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            registry_revision: self.stream_registry.registry_revision,
            outcome,
            renewed,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one stream subscription renewal authority review.
    ///
    /// Accepted renewal reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the renewed subscription
    /// replacing the matching active subscription. Rejected reviews produce a
    /// machine-readable application rejection and leave accepted state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_stream_subscription_renewal_authority_review(
        &self,
        review: ManifoldStreamSubscriptionRenewalAuthorityReview,
    ) -> Result<
        ManifoldStreamSubscriptionRenewalAuthorityApplication,
        ManifoldAuthorityValidationError,
    > {
        self.validate_authority_links()?;

        let application_id =
            stream_subscription_renewal_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_registry_revision = self.stream_registry.registry_revision;
        let stream_id = review.audit_event.request.stream_id.clone();
        let subscription_id = review.audit_event.request.subscription_id.clone();
        let from_active_subscriber_count = self.active_subscription_count(&stream_id);

        let (outcome, applied_snapshot, rejection) = match review.validate_against_snapshot(self) {
            Err(error) => (
                ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplicationRejected,
                None,
                Some(ManifoldAuthoritySnapshotApplicationRejection {
                    schema_id: authority_snapshot_application_rejection_schema_id(),
                    application_id: application_id.clone(),
                    rejection_code: DottedId::new(error.rejection_code())
                        .expect("authority rejection code is a valid dotted id"),
                    message: format!(
                        "stream subscription renewal review does not match authority snapshot: {error}"
                    ),
                    retryable: authority_application_validation_retryable(error.kind()),
                    current_authority_revision: self.authority_revision,
                }),
            ),
            Ok(())
                if review.outcome
                    == ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected =>
            {
                (
                    ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new("review_rejected")
                            .expect("rejection code literal is valid"),
                        message: "stream subscription renewal review did not renew a subscription"
                            .to_owned(),
                        retryable: review
                            .rejection
                            .as_ref()
                            .map(|rejection| rejection.retryable)
                            .unwrap_or(false),
                        current_authority_revision: self.authority_revision,
                    }),
                )
            }
            Ok(()) => {
                let Some(next_authority_revision) = self.authority_revision.next() else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        self.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                };
                let renewed_subscription = review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut next_snapshot = self.clone();
                next_snapshot.authority_revision = next_authority_revision;
                let Some(position) =
                    next_snapshot
                        .active_stream_subscriptions
                        .iter()
                        .position(|subscription| {
                            subscription.subscription_id == renewed_subscription.subscription_id
                        })
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        review.review_id.clone(),
                        renewed_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                next_snapshot.active_stream_subscriptions[position] = renewed_subscription;
                next_snapshot.validate_authority_links()?;
                (
                    ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplied,
                    Some(next_snapshot),
                    None,
                )
            }
        };

        let application = ManifoldStreamSubscriptionRenewalAuthorityApplication {
            schema_id: stream_subscription_renewal_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_registry_revision,
            stream_id,
            subscription_id,
            from_active_subscriber_count,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one module runtime-state change request.
    ///
    /// The review is source-only: it accepts or rejects proposed contract state
    /// and computes the resulting transition without starting, stopping, or
    /// contacting a runtime module.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_module_runtime_state_change(
        &self,
        request: ManifoldModuleRuntimeStateChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldModuleRuntimeStateAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.module_runtime_state_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let runtime_revision = self
            .module_runtime_state(&request.module_id)
            .map(|state| state.runtime_revision);
        let (outcome, accepted, transition, rejection) = match decision {
            ModuleRuntimeStateAuthorityDecision::Accepted { state, transition } => (
                ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted,
                Some(state),
                Some(transition),
                None,
            ),
            ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                current_runtime_revision,
            } => (
                ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected,
                None,
                None,
                Some(ManifoldModuleRuntimeStateRejection {
                    schema_id: module_runtime_state_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_runtime_revision,
                }),
            ),
        };

        let audit_event = ManifoldModuleRuntimeStateAuthorityAuditEvent {
            schema_id: module_runtime_state_authority_audit_event_schema_id(),
            event_id: module_runtime_state_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            module_id: request.module_id.clone(),
            prior_runtime_revision: runtime_revision,
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            transition: transition.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldModuleRuntimeStateAuthorityReview {
            schema_id: module_runtime_state_authority_review_schema_id(),
            review_id: module_runtime_state_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            module_id: audit_event.module_id.clone(),
            runtime_revision,
            outcome,
            accepted,
            transition,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one module runtime-state authority review to this snapshot.
    ///
    /// Accepted runtime-state reviews produce a new `ManifoldAuthoritySnapshot`
    /// with the authority revision advanced by one and the accepted module
    /// runtime state installed. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged. This is
    /// source-only: it does not start, stop, load, unload, signal, or contact a
    /// runtime module.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_module_runtime_state_authority_review(
        &self,
        review: ManifoldModuleRuntimeStateAuthorityReview,
    ) -> Result<ManifoldModuleRuntimeStateAuthorityApplication, ManifoldAuthorityValidationError>
    {
        self.validate_authority_links()?;

        let application_id = module_runtime_state_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let module_id = review.module_id.clone();
        let from_runtime_revision = self
            .module_runtime_state(&module_id)
            .map(|state| state.runtime_revision);

        let (outcome, applied_snapshot, rejection) =
            match review.validate_against_snapshot(self) {
                Err(error) => (
                    ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new(error.rejection_code())
                            .expect("authority rejection code is a valid dotted id"),
                        message: format!(
                            "module runtime-state review does not match authority snapshot: {error}"
                        ),
                        retryable: authority_application_validation_retryable(error.kind()),
                        current_authority_revision: self.authority_revision,
                    }),
                ),
                Ok(()) if review.outcome
                    == ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected =>
                {
                    (
                        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected,
                        None,
                        Some(ManifoldAuthoritySnapshotApplicationRejection {
                            schema_id: authority_snapshot_application_rejection_schema_id(),
                            application_id: application_id.clone(),
                            rejection_code: DottedId::new("review_rejected")
                                .expect("rejection code literal is valid"),
                            message: "module runtime-state review did not accept runtime state"
                                .to_owned(),
                            retryable: review
                                .rejection
                                .as_ref()
                                .map(|rejection| rejection.retryable)
                                .unwrap_or(false),
                            current_authority_revision: self.authority_revision,
                        }),
                    )
                }
                Ok(()) => {
                    let Some(next_authority_revision) = self.authority_revision.next() else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            self.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        ));
                    };
                    let accepted_state = review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?;
                    let mut next_snapshot = self.clone();
                    next_snapshot.authority_revision = next_authority_revision;
                    let Some(state) = next_snapshot
                        .module_runtime_states
                        .iter_mut()
                        .find(|state| state.module_id == accepted_state.module_id)
                    else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            accepted_state.module_id.to_string(),
                            ManifoldAuthorityValidationErrorKind::UnknownModule,
                        ));
                    };
                    *state = accepted_state;
                    next_snapshot.validate_authority_links()?;
                    (
                        ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplied,
                        Some(next_snapshot),
                        None,
                    )
                }
            };

        let application = ManifoldModuleRuntimeStateAuthorityApplication {
            schema_id: module_runtime_state_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            module_id,
            from_runtime_revision,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one host manifest change request.
    ///
    /// The review is source-only: it accepts or rejects proposed contract state
    /// and does not start host services, open endpoints, probe permissions, or
    /// mutate a live host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_host_manifest_change(
        &self,
        request: ManifoldHostManifestChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldHostManifestAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.host_manifest_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            HostManifestAuthorityDecision::Accepted(manifest) => (
                ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted,
                Some(manifest),
                None,
            ),
            HostManifestAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected,
                None,
                Some(ManifoldHostManifestRejection {
                    schema_id: host_manifest_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                }),
            ),
        };

        let audit_event = ManifoldHostManifestAuthorityAuditEvent {
            schema_id: host_manifest_authority_audit_event_schema_id(),
            event_id: host_manifest_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            host_id: self.host_manifest.host_id.clone(),
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldHostManifestAuthorityReview {
            schema_id: host_manifest_authority_review_schema_id(),
            review_id: host_manifest_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            host_id: audit_event.host_id.clone(),
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one host manifest authority review to this snapshot.
    ///
    /// Accepted host manifest reviews produce a new `ManifoldAuthoritySnapshot`
    /// with the authority revision advanced by one and the accepted host
    /// manifest installed. Rejected reviews produce a machine-readable
    /// application rejection and leave accepted state unchanged. This is
    /// source-only: it does not start host services, open endpoints, probe
    /// permissions, or mutate a live host.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_host_manifest_authority_review(
        &self,
        review: ManifoldHostManifestAuthorityReview,
    ) -> Result<ManifoldHostManifestAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = host_manifest_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let host_id = review.host_id.clone();

        let (outcome, applied_snapshot, rejection) =
            match review.validate_against_snapshot(self) {
                Err(error) => (
                    ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new(error.rejection_code())
                            .expect("authority rejection code is a valid dotted id"),
                        message: format!(
                            "host manifest review does not match authority snapshot: {error}"
                        ),
                        retryable: authority_application_validation_retryable(error.kind()),
                        current_authority_revision: self.authority_revision,
                    }),
                ),
                Ok(()) if review.outcome == ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected => {
                    (
                        ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplicationRejected,
                        None,
                        Some(ManifoldAuthoritySnapshotApplicationRejection {
                            schema_id: authority_snapshot_application_rejection_schema_id(),
                            application_id: application_id.clone(),
                            rejection_code: DottedId::new("review_rejected")
                                .expect("rejection code literal is valid"),
                            message: "host manifest review did not accept a host manifest"
                                .to_owned(),
                            retryable: review
                                .rejection
                                .as_ref()
                                .map(|rejection| rejection.retryable)
                                .unwrap_or(false),
                            current_authority_revision: self.authority_revision,
                        }),
                    )
                }
                Ok(()) => {
                    let Some(next_authority_revision) = self.authority_revision.next() else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            self.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        ));
                    };
                    let accepted_manifest = review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?;
                    let mut next_snapshot = self.clone();
                    next_snapshot.authority_revision = next_authority_revision;
                    next_snapshot.host_manifest = accepted_manifest;
                    next_snapshot.validate_authority_links()?;
                    (
                        ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplied,
                        Some(next_snapshot),
                        None,
                    )
                }
            };

        let application = ManifoldHostManifestAuthorityApplication {
            schema_id: host_manifest_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            host_id,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    /// Deterministically reviews one clock snapshot change request.
    ///
    /// The review is source-only: it accepts or rejects proposed contract state
    /// and does not read a live clock, alter host time, start a clock service,
    /// or contact a platform adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the authority snapshot
    /// itself is invalid, the review clock is inconsistent, or evidence refs are empty.
    pub fn review_clock_snapshot_change(
        &self,
        request: ManifoldClockSnapshotChangeRequest,
        recorded_clock: ManifoldClockSnapshot,
        evidence_refs: Vec<DottedId>,
    ) -> Result<ManifoldClockSnapshotAuthorityReview, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        if recorded_clock.clock_domain != self.clock_snapshot.clock_domain
            || recorded_clock.clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || recorded_clock.sequence < self.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                request.request_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        let decision = self.clock_snapshot_authority_decision(&request, &recorded_clock);
        let lease = request
            .lease_id
            .as_ref()
            .and_then(|lease_id| self.active_lease(lease_id))
            .cloned();
        let (outcome, accepted, rejection) = match decision {
            ClockSnapshotAuthorityDecision::Accepted(snapshot) => (
                ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted,
                Some(snapshot),
                None,
            ),
            ClockSnapshotAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } => (
                ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected,
                None,
                Some(ManifoldClockSnapshotRejection {
                    schema_id: clock_snapshot_rejection_schema_id(),
                    request_id: request.request_id.clone(),
                    rejection_code: DottedId::new(rejection_code)
                        .expect("rejection code is a valid dotted id"),
                    message,
                    retryable,
                    current_authority_revision: self.authority_revision,
                    current_clock_epoch_id: self.clock_snapshot.clock_epoch_id.clone(),
                    current_clock_sequence: self.clock_snapshot.sequence,
                }),
            ),
        };

        let audit_event = ManifoldClockSnapshotAuthorityAuditEvent {
            schema_id: clock_snapshot_authority_audit_event_schema_id(),
            event_id: clock_snapshot_authority_audit_event_id(&request.request_id, outcome),
            authority_id: self.authority_id.clone(),
            prior_authority_revision: self.authority_revision,
            prior_clock_snapshot: self.clock_snapshot.clone(),
            event_kind: outcome.into(),
            request,
            accepted: accepted.clone(),
            rejection: rejection.clone(),
            lease,
            recorded_clock,
            evidence_refs,
        };

        let review = ManifoldClockSnapshotAuthorityReview {
            schema_id: clock_snapshot_authority_review_schema_id(),
            review_id: clock_snapshot_authority_review_id(&audit_event.request.request_id),
            authority_id: self.authority_id.clone(),
            authority_revision: self.authority_revision,
            clock_domain: audit_event.prior_clock_snapshot.clock_domain.clone(),
            clock_epoch_id: audit_event.prior_clock_snapshot.clock_epoch_id.clone(),
            clock_sequence: audit_event.prior_clock_snapshot.sequence,
            outcome,
            accepted,
            rejection,
            audit_event,
        };
        review.validate_against_snapshot(self)?;
        Ok(review)
    }

    /// Deterministically applies one clock snapshot authority review to this snapshot.
    ///
    /// Accepted clock reviews produce a new `ManifoldAuthoritySnapshot` with
    /// the authority revision advanced by one and the accepted clock snapshot
    /// installed. Rejected reviews produce a machine-readable application
    /// rejection and leave accepted state unchanged. This is source-only: it
    /// does not read a live clock, alter host time, start a clock service, or
    /// contact a platform adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when this authority snapshot
    /// itself is invalid.
    pub fn apply_clock_snapshot_authority_review(
        &self,
        review: ManifoldClockSnapshotAuthorityReview,
    ) -> Result<ManifoldClockSnapshotAuthorityApplication, ManifoldAuthorityValidationError> {
        self.validate_authority_links()?;

        let application_id = clock_snapshot_authority_application_id(&review.review_id);
        let from_authority_revision = self.authority_revision;
        let from_clock_epoch_id = self.clock_snapshot.clock_epoch_id.clone();
        let from_clock_sequence = self.clock_snapshot.sequence;

        let (outcome, applied_snapshot, rejection) =
            match review.validate_against_snapshot(self) {
                Err(error) => (
                    ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected,
                    None,
                    Some(ManifoldAuthoritySnapshotApplicationRejection {
                        schema_id: authority_snapshot_application_rejection_schema_id(),
                        application_id: application_id.clone(),
                        rejection_code: DottedId::new(error.rejection_code())
                            .expect("authority rejection code is a valid dotted id"),
                        message: format!(
                            "clock snapshot review does not match authority snapshot: {error}"
                        ),
                        retryable: authority_application_validation_retryable(error.kind()),
                        current_authority_revision: self.authority_revision,
                    }),
                ),
                Ok(()) if review.outcome
                    == ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected =>
                {
                    (
                        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected,
                        None,
                        Some(ManifoldAuthoritySnapshotApplicationRejection {
                            schema_id: authority_snapshot_application_rejection_schema_id(),
                            application_id: application_id.clone(),
                            rejection_code: DottedId::new("review_rejected")
                                .expect("rejection code literal is valid"),
                            message: "clock snapshot review did not accept a clock snapshot"
                                .to_owned(),
                            retryable: review
                                .rejection
                                .as_ref()
                                .map(|rejection| rejection.retryable)
                                .unwrap_or(false),
                            current_authority_revision: self.authority_revision,
                        }),
                    )
                }
                Ok(()) => {
                    let Some(next_authority_revision) = self.authority_revision.next() else {
                        return Err(ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            self.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        ));
                    };
                    let accepted_clock = review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            review.review_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?;
                    let mut next_snapshot = self.clone();
                    next_snapshot.authority_revision = next_authority_revision;
                    next_snapshot.clock_snapshot = accepted_clock;
                    next_snapshot.validate_authority_links()?;
                    (
                        ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplied,
                        Some(next_snapshot),
                        None,
                    )
                }
            };

        let application = ManifoldClockSnapshotAuthorityApplication {
            schema_id: clock_snapshot_authority_application_schema_id(),
            application_id,
            authority_id: self.authority_id.clone(),
            from_authority_revision,
            from_clock_epoch_id,
            from_clock_sequence,
            outcome,
            applied_snapshot,
            rejection,
            review,
        };
        application.validate_against_snapshot(self)?;
        Ok(application)
    }

    fn command_descriptor(&self, command_id: &DottedId) -> Option<&ManifoldCommandDescriptor> {
        self.command_descriptors
            .iter()
            .find(|descriptor| &descriptor.command_id == command_id)
    }

    fn stream_manifest(&self, stream_id: &DottedId) -> Option<&ManifoldStreamManifest> {
        self.stream_registry
            .streams
            .iter()
            .find(|stream| &stream.stream_id == stream_id)
    }

    fn module_runtime_state(&self, module_id: &DottedId) -> Option<&ManifoldModuleRuntimeState> {
        self.module_runtime_states
            .iter()
            .find(|state| &state.module_id == module_id)
    }

    fn active_lease(&self, lease_id: &DottedId) -> Option<&ManifoldControlLease> {
        self.active_leases
            .iter()
            .find(|lease| &lease.lease_id == lease_id)
    }

    fn active_subscription_count(&self, stream_id: &DottedId) -> u32 {
        let count = self
            .active_stream_subscriptions
            .iter()
            .filter(|subscription| {
                subscription.state == ManifoldStreamSubscriptionState::Active
                    && &subscription.stream_id == stream_id
            })
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    fn active_stream_subscription(
        &self,
        subscription_id: &DottedId,
    ) -> Option<&ManifoldStreamSubscription> {
        self.active_stream_subscriptions
            .iter()
            .find(|subscription| &subscription.subscription_id == subscription_id)
    }

    fn command_authority_decision(
        &self,
        envelope: &ManifoldCommandEnvelope,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> CommandAuthorityDecision {
        let Some(descriptor) = self.command_descriptor(&envelope.command_id) else {
            return CommandAuthorityDecision::Rejected {
                rejection_code: "unknown_command",
                message: "command is not advertised by this authority".to_owned(),
                retryable: false,
            };
        };

        let active_lease = if let Some(lease_id) = &envelope.lease_id {
            let Some(lease) = self.active_lease(lease_id) else {
                return CommandAuthorityDecision::Rejected {
                    rejection_code: "unknown_lease",
                    message: "command references an unknown lease".to_owned(),
                    retryable: true,
                };
            };
            Some(lease)
        } else {
            None
        };

        if let Some(lease) = active_lease {
            if lease_expired_at(lease, recorded_clock) {
                return CommandAuthorityDecision::Rejected {
                    rejection_code: "expired_lease",
                    message: "command references a lease expired at the review clock".to_owned(),
                    retryable: true,
                };
            }
        }

        match envelope.validate_request(descriptor, self.authority_revision, active_lease) {
            Ok(()) => CommandAuthorityDecision::Accepted,
            Err(error) => CommandAuthorityDecision::Rejected {
                rejection_code: error.rejection_code(),
                message: error.message().to_owned(),
                retryable: command_validation_retryable(error.kind()),
            },
        }
    }

    fn lease_authority_decision(
        &self,
        request: &ManifoldControlLeaseRequest,
    ) -> LeaseAuthorityDecision {
        if request.expected_revision != self.authority_revision {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "stale_revision",
                message: "lease request expected revision does not match current revision"
                    .to_owned(),
                retryable: true,
                conflicting_lease_id: None,
            };
        }

        if request.requested_ttl_ms == 0 {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl",
                message: "lease request ttl must be greater than zero".to_owned(),
                retryable: false,
                conflicting_lease_id: None,
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised",
                message: "lease request capability is not advertised by the authority host"
                    .to_owned(),
                retryable: false,
                conflicting_lease_id: None,
            };
        }

        if let Some(conflicting_lease) = self
            .active_leases
            .iter()
            .find(|lease| lease.scope == request.scope && lease.state == LeaseState::Active)
        {
            return LeaseAuthorityDecision::Rejected {
                rejection_code: "lease_scope_busy",
                message: "lease request scope is already held by an active lease".to_owned(),
                retryable: true,
                conflicting_lease_id: Some(conflicting_lease.lease_id.clone()),
            };
        }

        LeaseAuthorityDecision::Accepted
    }

    fn lease_release_authority_decision(
        &self,
        request: &ManifoldControlLeaseReleaseRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> LeaseReleaseAuthorityDecision {
        if request.schema_id != control_lease_release_request_schema_id() {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "control lease release request schema is not supported".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "control lease release request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        let Some(lease) = self.active_lease(&request.lease_id) else {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "control lease release request references an unknown active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        };

        if lease.state != LeaseState::Active {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "control lease release request references a non-active lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "control lease release request references an expired lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        if lease.holder_id != request.holder_id {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "lease_holder_mismatch".to_owned(),
                message: "control lease release request holder does not own the lease".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
            };
        }

        if lease.scope != request.scope {
            return LeaseReleaseAuthorityDecision::Rejected {
                rejection_code: "lease_scope_mismatch".to_owned(),
                message: "control lease release request scope does not match the active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
            };
        }

        LeaseReleaseAuthorityDecision::Released(lease.clone())
    }

    fn lease_renewal_authority_decision(
        &self,
        request: &ManifoldControlLeaseRenewalRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> LeaseRenewalAuthorityDecision {
        if request.schema_id != control_lease_renewal_request_schema_id() {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "control lease renewal request schema is not supported".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "control lease renewal request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        }

        if request.requested_ttl_ms == 0 {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl".to_owned(),
                message: "control lease renewal request ttl must be greater than zero".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        }

        let Some(lease) = self.active_lease(&request.lease_id) else {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "control lease renewal request references an unknown active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: None,
            };
        };

        if lease.state != LeaseState::Active {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "control lease renewal request references a non-active lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "control lease renewal request references an expired lease".to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        if lease.holder_id != request.holder_id {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "lease_holder_mismatch".to_owned(),
                message: "control lease renewal request holder does not own the lease".to_owned(),
                retryable: false,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        if lease.scope != request.scope {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "lease_scope_mismatch".to_owned(),
                message: "control lease renewal request scope does not match the active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        let renewed_expires_at_ms =
            wall_unix_ms_u64(recorded_clock).saturating_add(request.requested_ttl_ms);
        if renewed_expires_at_ms <= lease.expires_at_ms {
            return LeaseRenewalAuthorityDecision::Rejected {
                rejection_code: "non_extending_renewal".to_owned(),
                message: "control lease renewal request does not extend the active lease"
                    .to_owned(),
                retryable: true,
                active_lease_count: self.active_leases.len(),
                current_expires_at_ms: Some(lease.expires_at_ms),
            };
        }

        LeaseRenewalAuthorityDecision::Renewed(ManifoldControlLease {
            schema_id: control_lease_schema_id(),
            lease_id: lease.lease_id.clone(),
            holder_id: lease.holder_id.clone(),
            scope: lease.scope.clone(),
            state: LeaseState::Active,
            granted_revision: self.authority_revision,
            expires_at_ms: renewed_expires_at_ms,
            required_capability: lease.required_capability.clone(),
        })
    }

    fn authority_expiry_sweep_decision(
        &self,
        request: &ManifoldAuthorityExpirySweepRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> AuthorityExpirySweepDecision {
        let expired_leases = self
            .active_leases
            .iter()
            .filter(|lease| lease_expired_at(lease, recorded_clock))
            .cloned()
            .collect::<Vec<_>>();
        let expired_stream_subscriptions = self
            .active_stream_subscriptions
            .iter()
            .filter(|subscription| stream_subscription_expired_at(subscription, recorded_clock))
            .cloned()
            .collect::<Vec<_>>();
        let expired_lease_count = expired_leases.len();
        let expired_subscription_count = expired_stream_subscriptions.len();

        if request.schema_id != authority_expiry_sweep_request_schema_id() {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "authority expiry sweep request schema is not supported".to_owned(),
                retryable: false,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "authority expiry sweep request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "authority expiry sweep request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        if expired_leases.is_empty() && expired_stream_subscriptions.is_empty() {
            return AuthorityExpirySweepDecision::Rejected {
                rejection_code: "no_expired_state".to_owned(),
                message:
                    "authority expiry sweep found no expired active leases or stream subscriptions"
                        .to_owned(),
                retryable: true,
                expired_lease_count,
                expired_subscription_count,
            };
        }

        AuthorityExpirySweepDecision::Accepted {
            expired_leases,
            expired_stream_subscriptions,
        }
    }

    fn stream_registry_authority_decision(
        &self,
        request: &ManifoldStreamRegistryChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamRegistryAuthorityDecision {
        if request.schema_id != stream_registry_change_request_schema_id() {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream registry request schema is not supported".to_owned(),
                retryable: false,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message: "stream registry request expected authority revision does not match current revision"
                    .to_owned(),
                retryable: true,
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "stream registry request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
            };
        }

        let Some(lease_id) = &request.lease_id else {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "stream registry change requires an active registry lease".to_owned(),
                retryable: true,
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "stream registry request references an unknown lease".to_owned(),
                retryable: true,
            };
        };

        if lease.state != LeaseState::Active {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "stream registry lease is not active".to_owned(),
                retryable: true,
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "stream registry lease is expired at the review clock".to_owned(),
                retryable: true,
            };
        }

        if lease.granted_revision > self.authority_revision {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "stream registry lease was granted after this authority revision"
                    .to_owned(),
                retryable: true,
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != registry_lease_scope()
            || lease.required_capability != request.required_capability
        {
            return StreamRegistryAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "stream registry request does not match the active lease".to_owned(),
                retryable: true,
            };
        }

        match self.apply_stream_registry_diff(&request.diff) {
            Ok(snapshot) => StreamRegistryAuthorityDecision::Accepted(snapshot),
            Err(rejection) => StreamRegistryAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
            },
        }
    }

    fn apply_stream_registry_diff(
        &self,
        diff: &ManifoldStreamRegistryDiff,
    ) -> Result<ManifoldStreamRegistrySnapshot, StreamRegistryDiffRejection> {
        if diff.schema_id != stream_registry_diff_schema_id() {
            return Err(StreamRegistryDiffRejection::new(
                "unsupported_schema",
                "stream registry diff schema is not supported",
                false,
            ));
        }

        if diff.from_revision != self.stream_registry.registry_revision {
            return Err(StreamRegistryDiffRejection::new(
                "registry_revision_mismatch",
                "stream registry diff from_revision does not match current registry revision",
                true,
            ));
        }

        let Some(next_revision) = self.stream_registry.registry_revision.next() else {
            return Err(StreamRegistryDiffRejection::new(
                "registry_revision_mismatch",
                "stream registry revision cannot advance",
                false,
            ));
        };
        if diff.to_revision != next_revision {
            return Err(StreamRegistryDiffRejection::new(
                "registry_revision_mismatch",
                "stream registry diff to_revision must advance by one",
                true,
            ));
        }

        if diff.added_streams.is_empty()
            && diff.removed_streams.is_empty()
            && diff.changed_streams.is_empty()
        {
            return Err(StreamRegistryDiffRejection::new(
                "empty_registry_diff",
                "stream registry diff has no changes",
                false,
            ));
        }

        let mut streams = self.stream_registry.streams.clone();

        for removed in &diff.removed_streams {
            if self.active_stream_id(&removed.stream_id) {
                return Err(StreamRegistryDiffRejection::new(
                    "active_stream_conflict",
                    "stream registry diff removes a stream still active in module runtime state",
                    true,
                ));
            }

            if self.active_subscription_count(&removed.stream_id) > 0 {
                return Err(StreamRegistryDiffRejection::new(
                    "active_subscription_conflict",
                    "stream registry diff removes a stream with active subscriptions",
                    true,
                ));
            }

            let Some(index) = streams
                .iter()
                .position(|stream| stream.stream_id == removed.stream_id)
            else {
                return Err(StreamRegistryDiffRejection::new(
                    "unknown_stream",
                    "stream registry diff removes a stream absent from the current registry",
                    true,
                ));
            };

            if streams[index] != *removed {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_diff_mismatch",
                    "stream registry diff remove entry does not match the current stream",
                    true,
                ));
            }

            streams.remove(index);
        }

        for change in &diff.changed_streams {
            if change.before.stream_id != change.stream_id
                || change.after.stream_id != change.stream_id
            {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_diff_mismatch",
                    "stream registry diff change entry has mismatched stream ids",
                    false,
                ));
            }

            let Some(index) = streams
                .iter()
                .position(|stream| stream.stream_id == change.stream_id)
            else {
                return Err(StreamRegistryDiffRejection::new(
                    "unknown_stream",
                    "stream registry diff changes a stream absent from the current registry",
                    true,
                ));
            };

            if streams[index] != change.before {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_diff_mismatch",
                    "stream registry diff before entry does not match the current stream",
                    true,
                ));
            }

            if change.after.source_module_id != change.before.source_module_id
                && self.active_stream_id(&change.stream_id)
            {
                return Err(StreamRegistryDiffRejection::new(
                    "active_stream_conflict",
                    "stream registry diff changes the source module for an active stream",
                    true,
                ));
            }

            let active_subscription_count = self.active_subscription_count(&change.stream_id);
            if active_subscription_count > 0 {
                for subscription in self
                    .active_stream_subscriptions
                    .iter()
                    .filter(|subscription| subscription.stream_id == change.stream_id)
                {
                    let offer_still_available = change.after.transport_offers.iter().any(|offer| {
                        offer.transport_id == subscription.transport_id
                            && offer.endpoint_id == subscription.endpoint_id
                    });
                    if !offer_still_available {
                        return Err(StreamRegistryDiffRejection::new(
                            "active_subscription_conflict",
                            "stream registry diff removes a transport offer used by an active subscription",
                            true,
                        ));
                    }

                    if subscription.subscriber_kind == ManifoldStreamSubscriberKind::Ui
                        && !change.after.subscription.ui_subscribable
                    {
                        return Err(StreamRegistryDiffRejection::new(
                            "active_subscription_conflict",
                            "stream registry diff disables UI subscription policy while UI subscriptions are active",
                            true,
                        ));
                    }
                }

                if let Some(max_subscribers) = change.after.subscription.max_subscribers {
                    if active_subscription_count > max_subscribers {
                        return Err(StreamRegistryDiffRejection::new(
                            "active_subscription_conflict",
                            "stream registry diff lowers the subscriber limit below active subscriptions",
                            true,
                        ));
                    }
                }
            }

            streams[index] = change.after.clone();
        }

        for added in &diff.added_streams {
            if streams
                .iter()
                .any(|stream| stream.stream_id == added.stream_id)
            {
                return Err(StreamRegistryDiffRejection::new(
                    "stream_already_exists",
                    "stream registry diff adds a stream id that already exists",
                    true,
                ));
            }
            streams.push(added.clone());
        }

        if let Some(stream_id) = duplicate_stream_id(&streams) {
            return Err(StreamRegistryDiffRejection::new(
                "duplicate_stream",
                format!("stream registry contains duplicate stream id {stream_id}"),
                false,
            ));
        }

        let snapshot = ManifoldStreamRegistrySnapshot {
            schema_id: stream_registry_snapshot_schema_id(),
            registry_revision: diff.to_revision,
            streams,
        };
        let module_ids = self
            .module_runtime_states
            .iter()
            .map(|state| state.module_id.clone())
            .collect::<Vec<_>>();
        if let Err(error) = snapshot.validate_source_modules(&module_ids) {
            return Err(StreamRegistryDiffRejection::new(
                error.rejection_code(),
                format!(
                    "stream registry diff references unknown source module {}",
                    error.rejected_id()
                ),
                false,
            ));
        }

        let endpoint_ids = self
            .host_manifest
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint_id.clone())
            .collect::<Vec<_>>();
        if let Err(error) = snapshot.validate_transport_endpoints(&endpoint_ids) {
            return Err(StreamRegistryDiffRejection::new(
                error.rejection_code(),
                format!(
                    "stream registry diff references unknown transport endpoint {}",
                    error.rejected_id()
                ),
                false,
            ));
        }

        Ok(snapshot)
    }

    fn stream_subscription_authority_decision(
        &self,
        request: &ManifoldStreamSubscriptionRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamSubscriptionAuthorityDecision {
        if request.schema_id != stream_subscription_request_schema_id() {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream subscription request schema is not supported".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "stream subscription request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "stream subscription request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.requested_ttl_ms == 0 {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl".to_owned(),
                message: "stream subscription ttl must be greater than zero".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "stream subscription request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        let active_subscriber_count = self.active_subscription_count(&request.stream_id);
        let Some(stream) = self.stream_manifest(&request.stream_id) else {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "unknown_stream".to_owned(),
                message: "stream subscription request references an unknown stream".to_owned(),
                retryable: true,
                active_subscriber_count,
            };
        };

        if request.subscriber_kind == ManifoldStreamSubscriberKind::Ui
            && !stream.subscription.ui_subscribable
        {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "subscription_not_allowed".to_owned(),
                message: "stream manifest does not allow direct UI subscriptions".to_owned(),
                retryable: false,
                active_subscriber_count,
            };
        }

        if let Some(max_subscribers) = stream.subscription.max_subscribers {
            if active_subscriber_count >= max_subscribers {
                return StreamSubscriptionAuthorityDecision::Rejected {
                    rejection_code: "subscriber_limit_reached".to_owned(),
                    message: "stream subscription would exceed the stream subscriber limit"
                        .to_owned(),
                    retryable: true,
                    active_subscriber_count,
                };
            }
        }

        let Some(offer) = stream
            .transport_offers
            .iter()
            .find(|offer| offer.transport_id == request.transport_id)
        else {
            return StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code: "unknown_transport".to_owned(),
                message: "stream subscription request selected an unknown transport offer"
                    .to_owned(),
                retryable: true,
                active_subscriber_count,
            };
        };

        if let Some(endpoint_id) = &offer.endpoint_id {
            if !self
                .host_manifest
                .endpoints
                .iter()
                .any(|endpoint| &endpoint.endpoint_id == endpoint_id)
            {
                return StreamSubscriptionAuthorityDecision::Rejected {
                    rejection_code: "unknown_transport_endpoint".to_owned(),
                    message:
                        "stream subscription request selected a transport with an unknown endpoint"
                            .to_owned(),
                    retryable: false,
                    active_subscriber_count,
                };
            }
        }

        StreamSubscriptionAuthorityDecision::Accepted(ManifoldStreamSubscription {
            schema_id: stream_subscription_schema_id(),
            subscription_id: stream_subscription_id(&request.request_id),
            request_id: request.request_id.clone(),
            subscriber_id: request.subscriber_id.clone(),
            subscriber_kind: request.subscriber_kind,
            stream_id: request.stream_id.clone(),
            transport_id: request.transport_id.clone(),
            endpoint_id: offer.endpoint_id.clone(),
            state: ManifoldStreamSubscriptionState::Active,
            accepted_authority_revision: self.authority_revision,
            accepted_registry_revision: self.stream_registry.registry_revision,
            accepted_at_ms: wall_unix_ms_u64(recorded_clock),
            expires_at_ms: wall_unix_ms_u64(recorded_clock)
                .saturating_add(request.requested_ttl_ms),
            required_capability: request.required_capability.clone(),
        })
    }

    fn stream_subscription_release_authority_decision(
        &self,
        request: &ManifoldStreamSubscriptionReleaseRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamSubscriptionReleaseAuthorityDecision {
        if request.schema_id != stream_subscription_release_request_schema_id() {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream subscription release request schema is not supported".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "stream subscription release request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "stream subscription release request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        }

        let Some(subscription) = self.active_stream_subscription(&request.subscription_id) else {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "unknown_subscription".to_owned(),
                message:
                    "stream subscription release request references an unknown active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
            };
        };

        if subscription.state != ManifoldStreamSubscriptionState::Active {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "inactive_subscription".to_owned(),
                message: "stream subscription release request references a non-active subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        if stream_subscription_expired_at(subscription, recorded_clock) {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "expired_subscription".to_owned(),
                message: "stream subscription release request references an expired subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        if subscription.subscriber_id != request.subscriber_id {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "subscriber_mismatch".to_owned(),
                message:
                    "stream subscription release request subscriber does not own the subscription"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        if subscription.stream_id != request.stream_id {
            return StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code: "stream_mismatch".to_owned(),
                message:
                    "stream subscription release request stream does not match the active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
            };
        }

        StreamSubscriptionReleaseAuthorityDecision::Released(subscription.clone())
    }

    fn stream_subscription_renewal_authority_decision(
        &self,
        request: &ManifoldStreamSubscriptionRenewalRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> StreamSubscriptionRenewalAuthorityDecision {
        if request.schema_id != stream_subscription_renewal_request_schema_id() {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "stream subscription renewal request schema is not supported".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "stream subscription renewal request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        if request.expected_registry_revision != self.stream_registry.registry_revision {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "registry_revision_mismatch".to_owned(),
                message:
                    "stream subscription renewal request expected registry revision does not match current registry"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        if request.requested_ttl_ms == 0 {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "invalid_ttl".to_owned(),
                message: "stream subscription renewal ttl must be greater than zero".to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        }

        let Some(subscription) = self.active_stream_subscription(&request.subscription_id) else {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "unknown_subscription".to_owned(),
                message:
                    "stream subscription renewal request references an unknown active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&request.stream_id),
                current_expires_at_ms: None,
            };
        };

        if subscription.state != ManifoldStreamSubscriptionState::Active {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "inactive_subscription".to_owned(),
                message: "stream subscription renewal request references a non-active subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if stream_subscription_expired_at(subscription, recorded_clock) {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "expired_subscription".to_owned(),
                message: "stream subscription renewal request references an expired subscription"
                    .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if subscription.subscriber_id != request.subscriber_id {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "subscriber_mismatch".to_owned(),
                message:
                    "stream subscription renewal request subscriber does not own the subscription"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if subscription.stream_id != request.stream_id {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "stream_mismatch".to_owned(),
                message:
                    "stream subscription renewal request stream does not match the active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        if subscription.transport_id != request.transport_id {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "transport_mismatch".to_owned(),
                message:
                    "stream subscription renewal request transport does not match the active subscription"
                        .to_owned(),
                retryable: true,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        let renewed_expires_at_ms =
            wall_unix_ms_u64(recorded_clock).saturating_add(request.requested_ttl_ms);
        if renewed_expires_at_ms <= subscription.expires_at_ms {
            return StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code: "non_extending_renewal".to_owned(),
                message:
                    "stream subscription renewal request does not extend the active subscription"
                        .to_owned(),
                retryable: false,
                active_subscriber_count: self.active_subscription_count(&subscription.stream_id),
                current_expires_at_ms: Some(subscription.expires_at_ms),
            };
        }

        StreamSubscriptionRenewalAuthorityDecision::Renewed(ManifoldStreamSubscription {
            schema_id: stream_subscription_schema_id(),
            subscription_id: subscription.subscription_id.clone(),
            request_id: subscription.request_id.clone(),
            subscriber_id: subscription.subscriber_id.clone(),
            subscriber_kind: subscription.subscriber_kind,
            stream_id: subscription.stream_id.clone(),
            transport_id: subscription.transport_id.clone(),
            endpoint_id: subscription.endpoint_id.clone(),
            state: ManifoldStreamSubscriptionState::Active,
            accepted_authority_revision: self.authority_revision,
            accepted_registry_revision: subscription.accepted_registry_revision,
            accepted_at_ms: wall_unix_ms_u64(recorded_clock),
            expires_at_ms: renewed_expires_at_ms,
            required_capability: subscription.required_capability.clone(),
        })
    }

    fn active_stream_id(&self, stream_id: &DottedId) -> bool {
        self.module_runtime_states.iter().any(|state| {
            state
                .active_streams
                .iter()
                .any(|active| active == stream_id)
        })
    }

    fn host_manifest_authority_decision(
        &self,
        request: &ManifoldHostManifestChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> HostManifestAuthorityDecision {
        if request.schema_id != host_manifest_change_request_schema_id() {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "host manifest request schema is not supported".to_owned(),
                retryable: false,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "host manifest request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message: "host manifest request capability is not advertised by the authority host"
                    .to_owned(),
                retryable: false,
            };
        }

        let Some(lease_id) = &request.lease_id else {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "host manifest change requires an active host-manifest lease".to_owned(),
                retryable: true,
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "host manifest request references an unknown lease".to_owned(),
                retryable: true,
            };
        };

        if lease.state != LeaseState::Active {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "host manifest lease is not active".to_owned(),
                retryable: true,
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "host manifest lease is expired at the review clock".to_owned(),
                retryable: true,
            };
        }

        if lease.granted_revision > self.authority_revision {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "host manifest lease was granted after this authority revision".to_owned(),
                retryable: true,
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != host_manifest_lease_scope()
            || lease.required_capability != request.required_capability
        {
            return HostManifestAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "host manifest request does not match the active lease".to_owned(),
                retryable: true,
            };
        }

        match self.validate_proposed_host_manifest(&request.proposed_manifest) {
            Ok(()) => HostManifestAuthorityDecision::Accepted(request.proposed_manifest.clone()),
            Err(rejection) => HostManifestAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
            },
        }
    }

    fn validate_proposed_host_manifest(
        &self,
        proposed: &ManifoldHostManifest,
    ) -> Result<(), HostManifestRejection> {
        if proposed.schema_id != host_manifest_schema_id() {
            return Err(HostManifestRejection::new(
                "unsupported_schema",
                "host manifest schema is not supported",
                false,
            ));
        }

        if proposed.host_id != self.host_manifest.host_id {
            return Err(HostManifestRejection::new(
                "host_id_mismatch",
                "host manifest proposal cannot change the authority host id",
                false,
            ));
        }

        if proposed.authority_role == AuthorityRole::None {
            return Err(HostManifestRejection::new(
                "missing_authority_role",
                "host manifest proposal must advertise an authority role",
                false,
            ));
        }

        if proposed.clock_domain != self.clock_snapshot.clock_domain {
            return Err(HostManifestRejection::new(
                "clock_domain_mismatch",
                "host manifest proposal clock domain does not match the authority clock",
                true,
            ));
        }

        if let Err(error) = proposed.validate_endpoint_security() {
            return Err(HostManifestRejection::new(
                "endpoint_security_mismatch",
                format!(
                    "host manifest proposal endpoint {} has an unsafe visibility/security pairing",
                    error.endpoint_id()
                ),
                false,
            ));
        }

        if let Some(endpoint_id) = duplicate_endpoint_id(&proposed.endpoints) {
            return Err(HostManifestRejection::new(
                "duplicate_endpoint",
                format!("host manifest proposal duplicates endpoint id {endpoint_id}"),
                false,
            ));
        }

        if let Some(capability) = duplicate_id(&proposed.capabilities) {
            return Err(HostManifestRejection::new(
                "duplicate_capability",
                format!("host manifest proposal duplicates capability {capability}"),
                false,
            ));
        }

        if let Some(backend) = duplicate_id(&proposed.supported_backends) {
            return Err(HostManifestRejection::new(
                "duplicate_backend",
                format!("host manifest proposal duplicates backend {backend}"),
                false,
            ));
        }

        for endpoint in &self.host_manifest.endpoints {
            if !proposed
                .endpoints
                .iter()
                .any(|known| known.endpoint_id == endpoint.endpoint_id)
            {
                return Err(HostManifestRejection::new(
                    "endpoint_in_use",
                    format!(
                        "host manifest proposal removes advertised endpoint {}",
                        endpoint.endpoint_id
                    ),
                    true,
                ));
            }
        }

        for stream in &self.stream_registry.streams {
            for offer in &stream.transport_offers {
                if let Some(endpoint_id) = &offer.endpoint_id {
                    if !proposed
                        .endpoints
                        .iter()
                        .any(|known| &known.endpoint_id == endpoint_id)
                    {
                        return Err(HostManifestRejection::new(
                            "endpoint_in_use",
                            format!(
                                "host manifest proposal removes endpoint {endpoint_id} used by stream {}",
                                stream.stream_id
                            ),
                            true,
                        ));
                    }
                }
            }
        }

        for lease in &self.active_leases {
            if !proposed
                .capabilities
                .iter()
                .any(|capability| capability == &lease.required_capability)
            {
                return Err(HostManifestRejection::new(
                    "capability_in_use",
                    format!(
                        "host manifest proposal removes capability {} used by active lease {}",
                        lease.required_capability, lease.lease_id
                    ),
                    true,
                ));
            }
        }

        for descriptor in &self.command_descriptors {
            if !proposed
                .capabilities
                .iter()
                .any(|capability| capability == &descriptor.required_capability)
            {
                return Err(HostManifestRejection::new(
                    "capability_in_use",
                    format!(
                        "host manifest proposal removes capability {} used by command {}",
                        descriptor.required_capability, descriptor.command_id
                    ),
                    true,
                ));
            }
        }

        for subscription in &self.active_stream_subscriptions {
            if !proposed
                .capabilities
                .iter()
                .any(|capability| capability == &subscription.required_capability)
            {
                return Err(HostManifestRejection::new(
                    "capability_in_use",
                    format!(
                        "host manifest proposal removes capability {} used by active stream subscription {}",
                        subscription.required_capability, subscription.subscription_id
                    ),
                    true,
                ));
            }
        }

        for state in &self.module_runtime_states {
            if let Some(backend) = &state.selected_backend {
                if !proposed
                    .supported_backends
                    .iter()
                    .any(|known| known == backend)
                {
                    return Err(HostManifestRejection::new(
                        "backend_in_use",
                        format!(
                            "host manifest proposal removes backend {backend} used by module {}",
                            state.module_id
                        ),
                        true,
                    ));
                }
            }
        }

        Ok(())
    }

    fn clock_snapshot_authority_decision(
        &self,
        request: &ManifoldClockSnapshotChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> ClockSnapshotAuthorityDecision {
        if request.schema_id != clock_snapshot_change_request_schema_id() {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "clock snapshot request schema is not supported".to_owned(),
                retryable: false,
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message:
                    "clock snapshot request expected authority revision does not match current revision"
                        .to_owned(),
                retryable: true,
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "clock snapshot request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
            };
        }

        let Some(lease_id) = &request.lease_id else {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "clock snapshot change requires an active clock lease".to_owned(),
                retryable: true,
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "clock snapshot request references an unknown lease".to_owned(),
                retryable: true,
            };
        };

        if lease.state != LeaseState::Active {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "clock snapshot lease is not active".to_owned(),
                retryable: true,
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "clock snapshot lease is expired at the review clock".to_owned(),
                retryable: true,
            };
        }

        if lease.granted_revision > self.authority_revision {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "clock snapshot lease was granted after this authority revision"
                    .to_owned(),
                retryable: true,
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != clock_snapshot_lease_scope()
            || lease.required_capability != request.required_capability
        {
            return ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "clock snapshot request does not match the active lease".to_owned(),
                retryable: true,
            };
        }

        match self.validate_proposed_clock_snapshot(request) {
            Ok(()) => ClockSnapshotAuthorityDecision::Accepted(request.proposed_snapshot.clone()),
            Err(rejection) => ClockSnapshotAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
            },
        }
    }

    fn validate_proposed_clock_snapshot(
        &self,
        request: &ManifoldClockSnapshotChangeRequest,
    ) -> Result<(), ClockSnapshotRejection> {
        let proposed = &request.proposed_snapshot;
        if proposed.schema_id != clock_snapshot_schema_id() {
            return Err(ClockSnapshotRejection::new(
                "unsupported_schema",
                "clock snapshot schema is not supported",
                false,
            ));
        }

        if request.from_clock_epoch_id != self.clock_snapshot.clock_epoch_id
            || request.from_clock_sequence != self.clock_snapshot.sequence
        {
            return Err(ClockSnapshotRejection::new(
                "clock_precondition_mismatch",
                "clock snapshot request precondition does not match the accepted clock snapshot",
                true,
            ));
        }

        if proposed.clock_domain != self.clock_snapshot.clock_domain
            || proposed.clock_domain != self.host_manifest.clock_domain
        {
            return Err(ClockSnapshotRejection::new(
                "clock_domain_mismatch",
                "clock snapshot proposal clock domain does not match the authority clock domain",
                true,
            ));
        }

        if proposed.clock_epoch_id != self.clock_snapshot.clock_epoch_id {
            return Err(ClockSnapshotRejection::new(
                "clock_epoch_mismatch",
                "clock snapshot proposal changes the clock epoch without an epoch transition contract",
                true,
            ));
        }

        let Some(next_sequence) = self.clock_snapshot.sequence.checked_add(1) else {
            return Err(ClockSnapshotRejection::new(
                "clock_sequence_mismatch",
                "accepted clock sequence cannot advance",
                false,
            ));
        };
        if proposed.sequence != next_sequence {
            return Err(ClockSnapshotRejection::new(
                "clock_sequence_mismatch",
                "clock snapshot proposal must advance the clock sequence by one",
                true,
            ));
        }

        if proposed.monotonic_elapsed_ns <= self.clock_snapshot.monotonic_elapsed_ns {
            return Err(ClockSnapshotRejection::new(
                "monotonic_time_regression",
                "clock snapshot proposal must advance monotonic elapsed time",
                true,
            ));
        }

        if proposed.wall_clock_adjustment_count < self.clock_snapshot.wall_clock_adjustment_count {
            return Err(ClockSnapshotRejection::new(
                "wall_clock_adjustment_regression",
                "clock snapshot proposal cannot reduce the wall-clock adjustment count",
                true,
            ));
        }

        Ok(())
    }

    fn module_runtime_state_authority_decision(
        &self,
        request: &ManifoldModuleRuntimeStateChangeRequest,
        recorded_clock: &ManifoldClockSnapshot,
    ) -> ModuleRuntimeStateAuthorityDecision {
        if request.schema_id != module_runtime_state_change_request_schema_id() {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "unsupported_schema".to_owned(),
                message: "module runtime-state request schema is not supported".to_owned(),
                retryable: false,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        if request.expected_authority_revision != self.authority_revision {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "stale_revision".to_owned(),
                message: "module runtime-state request expected authority revision does not match current revision"
                    .to_owned(),
                retryable: true,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        if !self
            .host_manifest
            .capabilities
            .iter()
            .any(|capability| capability == &request.required_capability)
        {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "capability_not_advertised".to_owned(),
                message:
                    "module runtime-state request capability is not advertised by the authority host"
                        .to_owned(),
                retryable: false,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        if request.proposed_state.module_id != request.module_id {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "module_id_mismatch".to_owned(),
                message: "module runtime-state request module id does not match proposed state"
                    .to_owned(),
                retryable: false,
                current_runtime_revision: self
                    .module_runtime_state(&request.module_id)
                    .map(|state| state.runtime_revision),
            };
        }

        let Some(current_state) = self.module_runtime_state(&request.module_id) else {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "unknown_module".to_owned(),
                message:
                    "module runtime-state request targets a module absent from authority state"
                        .to_owned(),
                retryable: true,
                current_runtime_revision: None,
            };
        };

        let Some(lease_id) = &request.lease_id else {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "missing_lease".to_owned(),
                message: "module runtime-state change requires an active module lease".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        };

        let Some(lease) = self.active_lease(lease_id) else {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "unknown_lease".to_owned(),
                message: "module runtime-state request references an unknown lease".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        };

        if lease.state != LeaseState::Active {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "inactive_lease".to_owned(),
                message: "module runtime-state lease is not active".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        if lease_expired_at(lease, recorded_clock) {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "expired_lease".to_owned(),
                message: "module runtime-state lease is expired at the review clock".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        if lease.granted_revision > self.authority_revision {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "lease_revision_ahead".to_owned(),
                message: "module runtime-state lease was granted after this authority revision"
                    .to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        if lease.holder_id != request.holder_id
            || lease.scope != request.module_id
            || lease.required_capability != request.required_capability
        {
            return ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: "lease_mismatch".to_owned(),
                message: "module runtime-state request does not match the active lease".to_owned(),
                retryable: true,
                current_runtime_revision: Some(current_state.runtime_revision),
            };
        }

        match self.validate_proposed_module_runtime_state(current_state, &request.proposed_state) {
            Ok(transition) => ModuleRuntimeStateAuthorityDecision::Accepted {
                state: request.proposed_state.clone(),
                transition,
            },
            Err(rejection) => ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code: rejection.rejection_code,
                message: rejection.message,
                retryable: rejection.retryable,
                current_runtime_revision: Some(current_state.runtime_revision),
            },
        }
    }

    fn validate_proposed_module_runtime_state(
        &self,
        current_state: &ManifoldModuleRuntimeState,
        proposed_state: &ManifoldModuleRuntimeState,
    ) -> Result<ManifoldModuleRuntimeTransition, ModuleRuntimeStateRejection> {
        if proposed_state.schema_id != module_runtime_state_schema_id() {
            return Err(ModuleRuntimeStateRejection::new(
                "unsupported_schema",
                "module runtime-state schema is not supported",
                false,
            ));
        }

        if proposed_state.module_id != current_state.module_id {
            return Err(ModuleRuntimeStateRejection::new(
                "module_id_mismatch",
                "module runtime-state proposal targets a different module",
                false,
            ));
        }

        if proposed_state.runtime_revision
            != current_state.runtime_revision.next().ok_or_else(|| {
                ModuleRuntimeStateRejection::new(
                    "runtime_revision_mismatch",
                    "module runtime revision cannot advance",
                    false,
                )
            })?
        {
            return Err(ModuleRuntimeStateRejection::new(
                "runtime_revision_mismatch",
                "module runtime-state proposal must advance the runtime revision by one",
                true,
            ));
        }

        if let Some(backend) = &proposed_state.selected_backend {
            if !self
                .host_manifest
                .supported_backends
                .iter()
                .any(|known| known == backend)
            {
                return Err(ModuleRuntimeStateRejection::new(
                    "missing_backend",
                    "module runtime-state proposal selects a backend absent from the authority host",
                    false,
                ));
            }
        }

        if proposed_state.lifecycle == ModuleLifecycleState::Stopped
            && !proposed_state.active_streams.is_empty()
        {
            return Err(ModuleRuntimeStateRejection::new(
                "lifecycle_state_conflict",
                "stopped module runtime-state cannot report active streams",
                true,
            ));
        }

        for stream_id in &proposed_state.active_streams {
            let Some(stream) = self
                .stream_registry
                .streams
                .iter()
                .find(|stream| &stream.stream_id == stream_id)
            else {
                return Err(ModuleRuntimeStateRejection::new(
                    "unknown_stream",
                    "module runtime-state proposal references an unknown active stream",
                    true,
                ));
            };

            if stream.source_module_id != proposed_state.module_id {
                return Err(ModuleRuntimeStateRejection::new(
                    "stream_owner_mismatch",
                    "module runtime-state proposal claims a stream owned by another module",
                    false,
                ));
            }
        }

        for command_id in &proposed_state.active_commands {
            if !self.command_ids.iter().any(|known| known == command_id) {
                return Err(ModuleRuntimeStateRejection::new(
                    "unknown_command",
                    "module runtime-state proposal references an unknown active command",
                    true,
                ));
            }
        }

        let transition = proposed_state.transition_from(current_state);
        if module_runtime_transition_is_empty(&transition) {
            return Err(ModuleRuntimeStateRejection::new(
                "empty_runtime_transition",
                "module runtime-state proposal has no lifecycle, health, backend, stream, command, or issue changes",
                false,
            ));
        }

        Ok(transition)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommandAuthorityDecision {
    Accepted,
    Rejected {
        rejection_code: &'static str,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseAuthorityDecision {
    Accepted,
    Rejected {
        rejection_code: &'static str,
        message: String,
        retryable: bool,
        conflicting_lease_id: Option<DottedId>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseReleaseAuthorityDecision {
    Released(ManifoldControlLease),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_lease_count: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LeaseRenewalAuthorityDecision {
    Renewed(ManifoldControlLease),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_lease_count: usize,
        current_expires_at_ms: Option<u64>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamRegistryAuthorityDecision {
    Accepted(ManifoldStreamRegistrySnapshot),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamSubscriptionAuthorityDecision {
    Accepted(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamSubscriptionReleaseAuthorityDecision {
    Released(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamSubscriptionRenewalAuthorityDecision {
    Renewed(ManifoldStreamSubscription),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        active_subscriber_count: u32,
        current_expires_at_ms: Option<u64>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorityExpirySweepDecision {
    Accepted {
        expired_leases: Vec<ManifoldControlLease>,
        expired_stream_subscriptions: Vec<ManifoldStreamSubscription>,
    },
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        expired_lease_count: usize,
        expired_subscription_count: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ModuleRuntimeStateAuthorityDecision {
    Accepted {
        state: ManifoldModuleRuntimeState,
        transition: ManifoldModuleRuntimeTransition,
    },
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
        current_runtime_revision: Option<Revision>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostManifestAuthorityDecision {
    Accepted(ManifoldHostManifest),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClockSnapshotAuthorityDecision {
    Accepted(ManifoldClockSnapshot),
    Rejected {
        rejection_code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StreamRegistryDiffRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl StreamRegistryDiffRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostManifestRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl HostManifestRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClockSnapshotRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl ClockSnapshotRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleRuntimeStateRejection {
    rejection_code: String,
    message: String,
    retryable: bool,
}

impl ModuleRuntimeStateRejection {
    fn new(rejection_code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            rejection_code: rejection_code.into(),
            message: message.into(),
            retryable,
        }
    }
}

/// Audit event for one command authority decision.
///
/// The event carries the request envelope plus exactly one accepted or rejected
/// result. It records enough local authority context for deterministic
/// validation without depending on the legacy broker runtime.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Event kind.
    pub event_kind: ManifoldCommandAuthorityAuditEventKind,
    /// Command request reviewed by authority.
    pub envelope: ManifoldCommandEnvelope,
    /// Accepted result. Present only for accepted events.
    pub accepted: Option<ManifoldCommandAck>,
    /// Rejected result. Present only for rejected events.
    pub rejection: Option<ManifoldCommandRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one command authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldCommandAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the command.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldCommandAuthorityReviewOutcome,
    /// Accepted command result. Present only for accepted reviews.
    pub accepted: Option<ManifoldCommandAck>,
    /// Rejected command result. Present only for rejected reviews.
    pub rejection: Option<ManifoldCommandRejection>,
    /// Audit event for the same command decision.
    pub audit_event: ManifoldCommandAuthorityAuditEvent,
}

impl ManifoldCommandAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.command_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldCommandAuthorityReviewOutcome::CommandAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldCommandAuthorityReviewOutcome::CommandRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldCommandAuthorityAuditEventKind::from(self.outcome) != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

/// Audit event for one control lease release authority decision.
///
/// The event carries the lease release request plus exactly one released lease
/// or rejected result. It records enough local authority context for
/// deterministic validation without owning timers or runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Active lease count observed before the decision.
    pub active_lease_count: usize,
    /// Event kind.
    pub event_kind: ManifoldControlLeaseReleaseAuthorityAuditEventKind,
    /// Lease release request reviewed by authority.
    pub request: ManifoldControlLeaseReleaseRequest,
    /// Released lease. Present only for released events.
    pub released: Option<ManifoldControlLease>,
    /// Rejected lease release result. Present only for rejected events.
    pub rejection: Option<ManifoldControlLeaseReleaseRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one control lease release authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the lease release request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldControlLeaseReleaseAuthorityReviewOutcome,
    /// Released lease. Present only for accepted release reviews.
    pub released: Option<ManifoldControlLease>,
    /// Rejected lease release result. Present only for rejected release reviews.
    pub rejection: Option<ManifoldControlLeaseReleaseRejection>,
    /// Audit event for the same lease release decision.
    pub audit_event: ManifoldControlLeaseReleaseAuthorityAuditEvent,
}

impl ManifoldControlLeaseReleaseAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_release_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.released != self.audit_event.released
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldControlLeaseReleaseAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldControlLeaseReleaseAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent lease release or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_release_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.active_lease_count != snapshot.active_leases.len() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_lease_count.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldControlLeaseReleaseAuthorityAuditEventKind::LeaseReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseReleaseAuthorityAuditEventKind::LeaseReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.lease_release_authority_decision(&self.request, &self.recorded_clock);

        if let Some(released) = &self.released {
            let LeaseReleaseAuthorityDecision::Released(expected_lease) = &expected_decision else {
                let rejected_value = match &expected_decision {
                    LeaseReleaseAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    LeaseReleaseAuthorityDecision::Released(_) => "released".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_lease_release_rejection_code(&rejected_value),
                ));
            };

            if released != expected_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    released.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let LeaseReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_revision != self.prior_authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.active_lease_count != *active_lease_count
                || rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one control lease release authority review.
///
/// This records the bridge from review-time lease release authority to
/// accepted authority state without owning command execution, lease renewal
/// timers, or host/runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseReleaseAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Lease released by the reviewed request.
    pub lease_id: DottedId,
    /// Lease scope released.
    pub lease_scope: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Application outcome.
    pub outcome: ManifoldControlLeaseReleaseAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldControlLeaseReleaseAuthorityReview,
}

impl ManifoldControlLeaseReleaseAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_release_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.lease_id != self.review.audit_event.request.lease_id
            || self.lease_scope != self.review.audit_event.request.scope
            || self.from_active_lease_count != snapshot.active_leases.len()
            || self.from_active_lease_count != self.review.audit_event.active_lease_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleased
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_stream_subscriptions != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                let released_lease = self.review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_leases = snapshot.active_leases.clone();
                let Some(position) = expected_leases
                    .iter()
                    .position(|lease| lease.lease_id == released_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        released_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                let removed = expected_leases.remove(position);
                if removed != released_lease || applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.lease_scope.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldControlLeaseReleaseAuthorityApplicationOutcome::LeaseReleaseApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldControlLeaseReleaseAuthorityReviewOutcome::LeaseReleaseRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Audit event for one control lease renewal authority decision.
///
/// The event carries the lease renewal request plus exactly one renewed lease
/// or rejected result. It records enough local authority context for
/// deterministic validation without owning timers or runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Active lease count observed before the decision.
    pub active_lease_count: usize,
    /// Event kind.
    pub event_kind: ManifoldControlLeaseRenewalAuthorityAuditEventKind,
    /// Lease renewal request reviewed by authority.
    pub request: ManifoldControlLeaseRenewalRequest,
    /// Renewed lease. Present only for renewed events.
    pub renewed: Option<ManifoldControlLease>,
    /// Rejected lease renewal result. Present only for rejected events.
    pub rejection: Option<ManifoldControlLeaseRenewalRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one control lease renewal authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the lease renewal request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldControlLeaseRenewalAuthorityReviewOutcome,
    /// Renewed lease. Present only for accepted renewal reviews.
    pub renewed: Option<ManifoldControlLease>,
    /// Rejected lease renewal result. Present only for rejected renewal reviews.
    pub rejection: Option<ManifoldControlLeaseRenewalRejection>,
    /// Audit event for the same lease renewal decision.
    pub audit_event: ManifoldControlLeaseRenewalAuthorityAuditEvent,
}

impl ManifoldControlLeaseRenewalAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_renewal_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.renewed != self.audit_event.renewed || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldControlLeaseRenewalAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldControlLeaseRenewalAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent lease renewal or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_renewal_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.active_lease_count != snapshot.active_leases.len() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_lease_count.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldControlLeaseRenewalAuthorityAuditEventKind::LeaseRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldControlLeaseRenewalAuthorityAuditEventKind::LeaseRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.lease_renewal_authority_decision(&self.request, &self.recorded_clock);

        if let Some(renewed) = &self.renewed {
            let LeaseRenewalAuthorityDecision::Renewed(expected_lease) = &expected_decision else {
                let rejected_value = match &expected_decision {
                    LeaseRenewalAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    LeaseRenewalAuthorityDecision::Renewed(_) => "renewed".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_lease_renewal_rejection_code(&rejected_value),
                ));
            };

            if renewed != expected_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    renewed.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let LeaseRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_lease_count,
                current_expires_at_ms,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_revision != self.prior_authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
                || rejection.active_lease_count != *active_lease_count
                || rejection.current_expires_at_ms != *current_expires_at_ms
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    authority_error_kind_for_lease_renewal_rejection_code(rejection_code),
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one control lease renewal authority review.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldControlLeaseRenewalAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Lease renewed by the reviewed request.
    pub lease_id: DottedId,
    /// Lease scope renewed.
    pub lease_scope: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Application outcome.
    pub outcome: ManifoldControlLeaseRenewalAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldControlLeaseRenewalAuthorityReview,
}

impl ManifoldControlLeaseRenewalAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.lease_renewal_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.lease_id != self.review.audit_event.request.lease_id
            || self.lease_scope != self.review.audit_event.request.scope
            || self.from_active_lease_count != snapshot.active_leases.len()
            || self.from_active_lease_count != self.review.audit_event.active_lease_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.lease_id.to_string(),
                ManifoldAuthorityValidationErrorKind::LeaseMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewed
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_stream_subscriptions != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                let renewed_lease = self.review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_leases = snapshot.active_leases.clone();
                let Some(position) = expected_leases
                    .iter()
                    .position(|lease| lease.lease_id == renewed_lease.lease_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        renewed_lease.lease_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownLease,
                    ));
                };
                expected_leases[position] = renewed_lease;
                if applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.lease_scope.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldControlLeaseRenewalAuthorityApplicationOutcome::LeaseRenewalApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldControlLeaseRenewalAuthorityReviewOutcome::LeaseRenewalRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Audit event for one authority expiry sweep decision.
///
/// The event carries the sweep request plus exactly one accepted expired-state
/// set or rejected result. It records enough authority context to validate
/// cleanup deterministically without owning timers, transports, or callbacks.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Stream-registry revision observed before the decision.
    pub prior_registry_revision: Revision,
    /// Event kind.
    pub event_kind: ManifoldAuthorityExpirySweepAuthorityAuditEventKind,
    /// Sweep request reviewed by authority.
    pub request: ManifoldAuthorityExpirySweepRequest,
    /// Expired active leases found at the review clock. Present only for accepted events.
    pub expired_leases: Vec<ManifoldControlLease>,
    /// Expired active stream subscriptions found at the review clock. Present only for accepted events.
    pub expired_stream_subscriptions: Vec<ManifoldStreamSubscription>,
    /// Rejected sweep result. Present only for rejected events.
    pub rejection: Option<ManifoldAuthorityExpirySweepRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one authority expiry sweep decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the sweep.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldAuthorityExpirySweepAuthorityReviewOutcome,
    /// Expired active leases accepted for removal.
    pub expired_leases: Vec<ManifoldControlLease>,
    /// Expired active stream subscriptions accepted for removal.
    pub expired_stream_subscriptions: Vec<ManifoldStreamSubscription>,
    /// Rejected sweep result. Present only for rejected reviews.
    pub rejection: Option<ManifoldAuthorityExpirySweepRejection>,
    /// Audit event for the same sweep decision.
    pub audit_event: ManifoldAuthorityExpirySweepAuthorityAuditEvent,
}

impl ManifoldAuthorityExpirySweepAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.expiry_sweep_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.registry_revision != snapshot.stream_registry.registry_revision
            || self.registry_revision != self.audit_event.prior_registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted => {
                if (self.expired_leases.is_empty() && self.expired_stream_subscriptions.is_empty())
                    || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "expired_state".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected => {
                if !self.expired_leases.is_empty()
                    || !self.expired_stream_subscriptions.is_empty()
                    || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.expired_leases != self.audit_event.expired_leases
            || self.expired_stream_subscriptions != self.audit_event.expired_stream_subscriptions
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldAuthorityExpirySweepAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldAuthorityExpirySweepAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent expiry sweep acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.expiry_sweep_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.prior_registry_revision != snapshot.stream_registry.registry_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpiredStateAccepted => {
                if (self.expired_leases.is_empty() && self.expired_stream_subscriptions.is_empty())
                    || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "expired_state".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpirySweepRejected => {
                if !self.expired_leases.is_empty()
                    || !self.expired_stream_subscriptions.is_empty()
                    || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.authority_expiry_sweep_decision(&self.request, &self.recorded_clock);

        match (&self.event_kind, expected_decision) {
            (
                ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpiredStateAccepted,
                AuthorityExpirySweepDecision::Accepted {
                    expired_leases,
                    expired_stream_subscriptions,
                },
            ) => {
                if self.expired_leases != expired_leases
                    || self.expired_stream_subscriptions != expired_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        self.request.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }
            }
            (
                ManifoldAuthorityExpirySweepAuthorityAuditEventKind::ExpirySweepRejected,
                AuthorityExpirySweepDecision::Rejected {
                    rejection_code,
                    message,
                    retryable,
                    expired_lease_count,
                    expired_subscription_count,
                },
            ) => {
                let rejection = self.rejection.as_ref().expect("rejection presence checked");
                if rejection.request_id != self.request.request_id {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        rejection.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                    ));
                }

                if rejection.current_authority_revision != self.prior_authority_revision
                    || rejection.current_registry_revision != self.prior_registry_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        rejection.current_authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                    ));
                }

                if rejection.rejection_code.as_str() != rejection_code
                    || rejection.message != message
                    || rejection.retryable != retryable
                    || rejection.expired_lease_count != expired_lease_count
                    || rejection.expired_subscription_count != expired_subscription_count
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        rejection.rejection_code.to_string(),
                        authority_error_kind_for_expiry_sweep_rejection_code(&rejection_code),
                    ));
                }
            }
            (_, AuthorityExpirySweepDecision::Accepted { .. }) => {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            }
            (_, AuthorityExpirySweepDecision::Rejected { rejection_code, .. }) => {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection_code.clone(),
                    authority_error_kind_for_expiry_sweep_rejection_code(&rejection_code),
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one authority expiry sweep review.
///
/// This records the bridge from review-time expiry authority to accepted
/// authority state without owning live timer, holder, subscriber, transport,
/// provider, or host behavior.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityExpirySweepAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Stream-registry revision before applying the review.
    pub from_registry_revision: Revision,
    /// Request applied or rejected.
    pub request_id: DottedId,
    /// Number of active leases before applying the review.
    pub from_active_lease_count: usize,
    /// Number of active stream subscriptions before applying the review.
    pub from_active_subscription_count: usize,
    /// Number of leases removed by an accepted application.
    pub expired_lease_count: usize,
    /// Number of stream subscriptions removed by an accepted application.
    pub expired_subscription_count: usize,
    /// Application outcome.
    pub outcome: ManifoldAuthorityExpirySweepAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldAuthorityExpirySweepAuthorityReview,
}

impl ManifoldAuthorityExpirySweepAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.expiry_sweep_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_registry_revision != snapshot.stream_registry.registry_revision
            || self.from_registry_revision != self.review.registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.request_id != self.review.audit_event.request.request_id
            || self.from_active_lease_count != snapshot.active_leases.len()
            || self.from_active_subscription_count != snapshot.active_stream_subscriptions.len()
            || self.expired_lease_count != self.review.expired_leases.len()
            || self.expired_subscription_count != self.review.expired_stream_subscriptions.len()
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.request_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpiredStateApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let expired_lease_ids = self
                    .review
                    .expired_leases
                    .iter()
                    .map(|lease| lease.lease_id.clone())
                    .collect::<Vec<_>>();
                let mut expected_leases = snapshot.active_leases.clone();
                expected_leases
                    .retain(|lease| !expired_lease_ids.iter().any(|id| id == &lease.lease_id));
                if applied.active_leases != expected_leases {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                    ));
                }

                let expired_subscription_ids = self
                    .review
                    .expired_stream_subscriptions
                    .iter()
                    .map(|subscription| subscription.subscription_id.clone())
                    .collect::<Vec<_>>();
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                expected_subscriptions.retain(|subscription| {
                    !expired_subscription_ids
                        .iter()
                        .any(|id| id == &subscription.subscription_id)
                });
                if applied.active_stream_subscriptions != expected_subscriptions {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.request_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldAuthorityExpirySweepAuthorityApplicationOutcome::ExpirySweepApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Audit event for one stream-registry authority decision.
///
/// The event carries the registry change request plus exactly one accepted
/// snapshot or rejected result. It records enough authority context for
/// deterministic validation without publishing streams or opening transports.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Stream-registry revision observed before the decision.
    pub prior_registry_revision: Revision,
    /// Event kind.
    pub event_kind: ManifoldStreamRegistryAuthorityAuditEventKind,
    /// Registry change request reviewed by authority.
    pub request: ManifoldStreamRegistryChangeRequest,
    /// Accepted registry snapshot. Present only for accepted events.
    pub accepted: Option<ManifoldStreamRegistrySnapshot>,
    /// Rejected registry result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamRegistryRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream-registry authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the registry change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamRegistryAuthorityReviewOutcome,
    /// Accepted registry snapshot. Present only for accepted reviews.
    pub accepted: Option<ManifoldStreamRegistrySnapshot>,
    /// Rejected registry result. Present only for rejected reviews.
    pub rejection: Option<ManifoldStreamRegistryRejection>,
    /// Audit event for the same registry decision.
    pub audit_event: ManifoldStreamRegistryAuthorityAuditEvent,
}

impl ManifoldStreamRegistryAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_registry_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.registry_revision != snapshot.stream_registry.registry_revision
            || self.registry_revision != self.audit_event.prior_registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldStreamRegistryAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

/// Machine-readable rejection for applying an authority review to accepted state.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthoritySnapshotApplicationRejection {
    /// Schema identifier for this rejection.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Application that was rejected.
    pub application_id: DottedId,
    /// Stable rejection code.
    pub rejection_code: DottedId,
    /// Display-safe rejection message.
    pub message: String,
    /// Whether retrying after refreshing state may help.
    pub retryable: bool,
    /// Current authority revision observed by the application attempt.
    pub current_authority_revision: Revision,
}

/// Deterministic application result for one stream-registry authority review.
///
/// This records the bridge from review-time authority to accepted authority
/// state without owning live publication, transport, or runtime mutation.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamRegistryAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Stream-registry revision before applying the review.
    pub from_registry_revision: Revision,
    /// Application outcome.
    pub outcome: ManifoldStreamRegistryAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamRegistryAuthorityReview,
}

impl ManifoldStreamRegistryAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_registry_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_registry_revision != snapshot.stream_registry.registry_revision
            || self.from_registry_revision != self.review.registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldStreamRegistryAuthorityApplicationOutcome::RegistrySnapshotApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::RegistryMismatch,
                    ));
                }

                if applied.stream_registry
                    != self
                        .review
                        .accepted
                        .clone()
                        .unwrap_or_else(|| snapshot.stream_registry.clone())
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.stream_registry.registry_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::RegistryMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamRegistryAuthorityApplicationOutcome::RegistryApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected
                {
                    if rejection.rejection_code.as_str() != "review_rejected" {
                        return Err(ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            rejection.rejection_code.to_string(),
                            ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                        ));
                    }
                }

                Ok(())
            }
        }
    }
}

/// Audit event for one stream subscription authority decision.
///
/// The event carries the subscription request plus exactly one accepted
/// subscription or rejected result. It records enough authority context for
/// deterministic validation without opening transports or notifying subscribers.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Stream-registry revision observed before the decision.
    pub prior_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
    /// Event kind.
    pub event_kind: ManifoldStreamSubscriptionAuthorityAuditEventKind,
    /// Subscription request reviewed by authority.
    pub request: ManifoldStreamSubscriptionRequest,
    /// Accepted subscription. Present only for accepted events.
    pub accepted: Option<ManifoldStreamSubscription>,
    /// Rejected subscription result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamSubscriptionRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream subscription authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the subscription request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamSubscriptionAuthorityReviewOutcome,
    /// Accepted subscription. Present only for accepted reviews.
    pub accepted: Option<ManifoldStreamSubscription>,
    /// Rejected subscription result. Present only for rejected reviews.
    pub rejection: Option<ManifoldStreamSubscriptionRejection>,
    /// Audit event for the same subscription decision.
    pub audit_event: ManifoldStreamSubscriptionAuthorityAuditEvent,
}

impl ManifoldStreamSubscriptionAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_subscription_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.registry_revision != snapshot.stream_registry.registry_revision
            || self.registry_revision != self.audit_event.prior_registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldStreamSubscriptionAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldStreamSubscriptionAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent subscription acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_subscription_audit_event.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.prior_registry_revision != snapshot.stream_registry.registry_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.active_subscriber_count
            != snapshot.active_subscription_count(&self.request.stream_id)
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldStreamSubscriptionAuthorityAuditEventKind::SubscriptionAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionAuthorityAuditEventKind::SubscriptionRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision =
            snapshot.stream_subscription_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let StreamSubscriptionAuthorityDecision::Accepted(expected_subscription) =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamSubscriptionAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    StreamSubscriptionAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_subscription_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_subscription {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamSubscriptionAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_registry_revision != self.prior_registry_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.active_subscriber_count != *active_subscriber_count
                || rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one stream subscription authority review.
///
/// This records the bridge from review-time subscription authority to accepted
/// authority state without owning live transport, callbacks, or provider runtime
/// work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Stream-registry revision before applying the review.
    pub from_registry_revision: Revision,
    /// Stream whose subscriber set was reviewed.
    pub stream_id: DottedId,
    /// Active subscriber count before applying the review.
    pub from_active_subscriber_count: u32,
    /// Application outcome.
    pub outcome: ManifoldStreamSubscriptionAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamSubscriptionAuthorityReview,
}

impl ManifoldStreamSubscriptionAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_subscription_application.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_registry_revision != snapshot.stream_registry.registry_revision
            || self.from_registry_revision != self.review.registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.stream_id != self.review.audit_event.request.stream_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.stream_id.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        let snapshot_active_count = snapshot.active_subscription_count(&self.stream_id);
        if self.from_active_subscriber_count != snapshot_active_count
            || self.from_active_subscriber_count != self.review.audit_event.active_subscriber_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                let accepted_subscription = self.review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                expected_subscriptions.push(accepted_subscription);
                if applied.active_stream_subscriptions != expected_subscriptions {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamSubscriptionAuthorityApplicationOutcome::SubscriptionApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Stream subscription release authority audit event.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Stream-registry revision observed before the decision.
    pub prior_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
    /// Event kind.
    pub event_kind: ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind,
    /// Release request reviewed by authority.
    pub request: ManifoldStreamSubscriptionReleaseRequest,
    /// Released subscription. Present only for released events.
    pub released: Option<ManifoldStreamSubscription>,
    /// Rejected release result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamSubscriptionReleaseRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream subscription release authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the release request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome,
    /// Released subscription. Present only for accepted release reviews.
    pub released: Option<ManifoldStreamSubscription>,
    /// Rejected release result. Present only for rejected release reviews.
    pub rejection: Option<ManifoldStreamSubscriptionReleaseRejection>,
    /// Audit event for the same release decision.
    pub audit_event: ManifoldStreamSubscriptionReleaseAuthorityAuditEvent,
}

impl ManifoldStreamSubscriptionReleaseAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_release_review.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.registry_revision != snapshot.stream_registry.registry_revision
            || self.registry_revision != self.audit_event.prior_registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.released != self.audit_event.released
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldStreamSubscriptionReleaseAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent subscription release or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_release_audit_event.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.prior_registry_revision != snapshot.stream_registry.registry_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.active_subscriber_count
            != snapshot.active_subscription_count(&self.request.stream_id)
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind::SubscriptionReleased => {
                if self.released.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind::SubscriptionReleaseRejected => {
                if self.released.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision = snapshot
            .stream_subscription_release_authority_decision(&self.request, &self.recorded_clock);

        if let Some(released) = &self.released {
            let StreamSubscriptionReleaseAuthorityDecision::Released(expected_subscription) =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamSubscriptionReleaseAuthorityDecision::Rejected {
                        rejection_code, ..
                    } => rejection_code.clone(),
                    StreamSubscriptionReleaseAuthorityDecision::Released(_) => {
                        "released".to_owned()
                    }
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_subscription_release_rejection_code(
                        &rejected_value,
                    ),
                ));
            };

            if released != expected_subscription {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    released.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamSubscriptionReleaseAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_registry_revision != self.prior_registry_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.active_subscriber_count != *active_subscriber_count
                || rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one stream subscription release authority review.
///
/// This records the bridge from review-time release authority to accepted
/// authority state without owning live transport teardown, callbacks, or
/// provider runtime work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionReleaseAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Stream-registry revision before applying the review.
    pub from_registry_revision: Revision,
    /// Stream whose subscriber set was reviewed.
    pub stream_id: DottedId,
    /// Subscription released by the reviewed request.
    pub subscription_id: DottedId,
    /// Active subscriber count before applying the review.
    pub from_active_subscriber_count: u32,
    /// Application outcome.
    pub outcome: ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamSubscriptionReleaseAuthorityReview,
}

impl ManifoldStreamSubscriptionReleaseAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_release_application.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_registry_revision != snapshot.stream_registry.registry_revision
            || self.from_registry_revision != self.review.registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.stream_id != self.review.audit_event.request.stream_id
            || self.subscription_id != self.review.audit_event.request.subscription_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.subscription_id.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        let snapshot_active_count = snapshot.active_subscription_count(&self.stream_id);
        if self.from_active_subscriber_count != snapshot_active_count
            || self.from_active_subscriber_count != self.review.audit_event.active_subscriber_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                let released_subscription = self.review.released.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "released".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                let Some(position) = expected_subscriptions.iter().position(|subscription| {
                    subscription.subscription_id == released_subscription.subscription_id
                }) else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        released_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                let removed = expected_subscriptions.remove(position);
                if removed != released_subscription
                    || applied.active_stream_subscriptions != expected_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome::SubscriptionReleaseApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Stream subscription renewal authority audit event.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Stream-registry revision observed before the decision.
    pub prior_registry_revision: Revision,
    /// Active subscriber count observed for the requested stream.
    pub active_subscriber_count: u32,
    /// Event kind.
    pub event_kind: ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind,
    /// Renewal request reviewed by authority.
    pub request: ManifoldStreamSubscriptionRenewalRequest,
    /// Renewed subscription. Present only for accepted renewal events.
    pub renewed: Option<ManifoldStreamSubscription>,
    /// Rejected renewal result. Present only for rejected events.
    pub rejection: Option<ManifoldStreamSubscriptionRenewalRejection>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one stream subscription renewal authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the renewal request.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Stream-registry revision used by this review.
    pub registry_revision: Revision,
    /// Review outcome.
    pub outcome: ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome,
    /// Renewed subscription. Present only for accepted renewal reviews.
    pub renewed: Option<ManifoldStreamSubscription>,
    /// Rejected renewal result. Present only for rejected renewal reviews.
    pub rejection: Option<ManifoldStreamSubscriptionRenewalRejection>,
    /// Audit event for the same renewal decision.
    pub audit_event: ManifoldStreamSubscriptionRenewalAuthorityAuditEvent,
}

impl ManifoldStreamSubscriptionRenewalAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_renewal_review.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.registry_revision != snapshot.stream_registry.registry_revision
            || self.registry_revision != self.audit_event.prior_registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.renewed != self.audit_event.renewed || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

impl ManifoldStreamSubscriptionRenewalAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent subscription renewal or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_renewal_audit_event.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.prior_registry_revision != snapshot.stream_registry.registry_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.active_subscriber_count
            != snapshot.active_subscription_count(&self.request.stream_id)
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind::SubscriptionRenewed => {
                if self.renewed.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind::SubscriptionRenewalRejected => {
                if self.renewed.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let expected_decision = snapshot
            .stream_subscription_renewal_authority_decision(&self.request, &self.recorded_clock);

        if let Some(renewed) = &self.renewed {
            let StreamSubscriptionRenewalAuthorityDecision::Renewed(expected_subscription) =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamSubscriptionRenewalAuthorityDecision::Rejected {
                        rejection_code, ..
                    } => rejection_code.clone(),
                    StreamSubscriptionRenewalAuthorityDecision::Renewed(_) => "renewed".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_subscription_renewal_rejection_code(
                        &rejected_value,
                    ),
                ));
            };

            if renewed != expected_subscription {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    renewed.subscription_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamSubscriptionRenewalAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                active_subscriber_count,
                current_expires_at_ms,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_registry_revision != self.prior_registry_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.active_subscriber_count != *active_subscriber_count
                || rejection.current_expires_at_ms != *current_expires_at_ms
                || rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

/// Deterministic application result for one stream subscription renewal authority review.
///
/// This records the bridge from review-time renewal authority to accepted
/// authority state without owning live transport setup, callbacks, or provider
/// runtime work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldStreamSubscriptionRenewalAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Stream-registry revision before applying the review.
    pub from_registry_revision: Revision,
    /// Stream whose subscriber set was reviewed.
    pub stream_id: DottedId,
    /// Subscription renewed by the reviewed request.
    pub subscription_id: DottedId,
    /// Active subscriber count before applying the review.
    pub from_active_subscriber_count: u32,
    /// Application outcome.
    pub outcome: ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldStreamSubscriptionRenewalAuthorityReview,
}

impl ManifoldStreamSubscriptionRenewalAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str()
            != "rusty.manifold.authority.stream_subscription_renewal_application.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_registry_revision != snapshot.stream_registry.registry_revision
            || self.from_registry_revision != self.review.registry_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.stream_id != self.review.audit_event.request.stream_id
            || self.subscription_id != self.review.audit_event.request.subscription_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.subscription_id.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        let snapshot_active_count = snapshot.active_subscription_count(&self.stream_id);
        if self.from_active_subscriber_count != snapshot_active_count
            || self.from_active_subscriber_count != self.review.audit_event.active_subscriber_count
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_active_subscriber_count.to_string(),
                ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                let renewed_subscription = self.review.renewed.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "renewed".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_subscriptions = snapshot.active_stream_subscriptions.clone();
                let Some(position) = expected_subscriptions.iter().position(|subscription| {
                    subscription.subscription_id == renewed_subscription.subscription_id
                }) else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        renewed_subscription.subscription_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownSubscription,
                    ));
                };
                expected_subscriptions[position] = renewed_subscription;
                if applied.active_stream_subscriptions != expected_subscriptions {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.stream_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::SubscriptionMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome::SubscriptionRenewalApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Deterministic application result for one module runtime-state authority review.
///
/// This records the bridge from review-time runtime-state authority to accepted
/// authority state without owning process lifecycle, module loading, or runtime
/// signaling.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Module whose runtime state was reviewed.
    pub module_id: DottedId,
    /// Runtime revision before applying the review, if the module is known.
    pub from_runtime_revision: Option<Revision>,
    /// Application outcome.
    pub outcome: ManifoldModuleRuntimeStateAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldModuleRuntimeStateAuthorityReview,
}

impl ManifoldModuleRuntimeStateAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.module_runtime_state_application.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        let snapshot_runtime_revision = snapshot
            .module_runtime_state(&self.module_id)
            .map(|state| state.runtime_revision);
        if self.module_id != self.review.module_id
            || self.module_id != self.review.audit_event.module_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.module_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
            ));
        }

        if self.from_runtime_revision != snapshot_runtime_revision
            || self.from_runtime_revision != self.review.runtime_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_runtime_revision
                    .map(|revision| revision.get().to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                    || applied.active_stream_subscriptions
                        != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                    ));
                }

                let accepted = self.review.accepted.clone().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    )
                })?;
                let mut expected_runtime_states = snapshot.module_runtime_states.clone();
                let Some(runtime_state) = expected_runtime_states
                    .iter_mut()
                    .find(|state| state.module_id == accepted.module_id)
                else {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        accepted.module_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::UnknownModule,
                    ));
                };
                *runtime_state = accepted;

                if applied.module_runtime_states != expected_runtime_states {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.module_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldModuleRuntimeStateAuthorityApplicationOutcome::RuntimeStateApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

/// Audit event for one module runtime-state authority decision.
///
/// The event carries the runtime-state change request plus exactly one accepted
/// state/transition pair or rejected result. It records enough authority
/// context for deterministic validation without performing lifecycle work.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Module being reviewed.
    pub module_id: DottedId,
    /// Runtime revision observed before the decision, if the module is known.
    pub prior_runtime_revision: Option<Revision>,
    /// Event kind.
    pub event_kind: ManifoldModuleRuntimeStateAuthorityAuditEventKind,
    /// Runtime-state change request reviewed by authority.
    pub request: ManifoldModuleRuntimeStateChangeRequest,
    /// Accepted runtime-state snapshot. Present only for accepted events.
    pub accepted: Option<ManifoldModuleRuntimeState>,
    /// Computed transition. Present only for accepted events.
    pub transition: Option<ManifoldModuleRuntimeTransition>,
    /// Rejected runtime-state result. Present only for rejected events.
    pub rejection: Option<ManifoldModuleRuntimeStateRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one module runtime-state authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldModuleRuntimeStateAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the runtime-state change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Module being reviewed.
    pub module_id: DottedId,
    /// Runtime revision used by this review, if the module is known.
    pub runtime_revision: Option<Revision>,
    /// Review outcome.
    pub outcome: ManifoldModuleRuntimeStateAuthorityReviewOutcome,
    /// Accepted runtime-state snapshot. Present only for accepted reviews.
    pub accepted: Option<ManifoldModuleRuntimeState>,
    /// Computed transition. Present only for accepted reviews.
    pub transition: Option<ManifoldModuleRuntimeTransition>,
    /// Rejected runtime-state result. Present only for rejected reviews.
    pub rejection: Option<ManifoldModuleRuntimeStateRejection>,
    /// Audit event for the same runtime-state decision.
    pub audit_event: ManifoldModuleRuntimeStateAuthorityAuditEvent,
}

impl ManifoldModuleRuntimeStateAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.module_runtime_state_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        let snapshot_runtime_revision = snapshot
            .module_runtime_state(&self.module_id)
            .map(|state| state.runtime_revision);
        if self.module_id != self.audit_event.module_id
            || self.module_id != self.audit_event.request.module_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.module_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
            ));
        }

        if self.runtime_revision != snapshot_runtime_revision
            || self.runtime_revision != self.audit_event.prior_runtime_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.runtime_revision
                    .map(|revision| revision.get().to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
            ));
        }

        match self.outcome {
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted => {
                if self.accepted.is_none() || self.transition.is_none() || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected => {
                if self.accepted.is_some() || self.transition.is_some() || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.transition != self.audit_event.transition
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldModuleRuntimeStateAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

/// Audit event for one host manifest authority decision.
///
/// The event carries the host manifest change request plus exactly one accepted
/// manifest or rejected result. It records enough authority context for
/// deterministic validation without probing or mutating a host.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Host whose manifest was reviewed.
    pub host_id: DottedId,
    /// Event kind.
    pub event_kind: ManifoldHostManifestAuthorityAuditEventKind,
    /// Host manifest change request reviewed by authority.
    pub request: ManifoldHostManifestChangeRequest,
    /// Accepted host manifest. Present only for accepted events.
    pub accepted: Option<ManifoldHostManifest>,
    /// Rejected host manifest result. Present only for rejected events.
    pub rejection: Option<ManifoldHostManifestRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one host manifest authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the host manifest change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Host whose manifest was reviewed.
    pub host_id: DottedId,
    /// Review outcome.
    pub outcome: ManifoldHostManifestAuthorityReviewOutcome,
    /// Accepted host manifest. Present only for accepted reviews.
    pub accepted: Option<ManifoldHostManifest>,
    /// Rejected host manifest result. Present only for rejected reviews.
    pub rejection: Option<ManifoldHostManifestRejection>,
    /// Audit event for the same host manifest decision.
    pub audit_event: ManifoldHostManifestAuthorityAuditEvent,
}

impl ManifoldHostManifestAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.host_manifest_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.host_id != snapshot.host_manifest.host_id
            || self.host_id != self.audit_event.host_id
            || self.host_id != self.audit_event.request.proposed_manifest.host_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostIdMismatch,
            ));
        }

        match self.outcome {
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldHostManifestAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

/// Deterministic application result for one host manifest authority review.
///
/// This records the bridge from review-time host manifest authority to accepted
/// authority state without owning host service startup, endpoint opening, or
/// permission probing.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldHostManifestAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Host whose manifest was reviewed.
    pub host_id: DottedId,
    /// Application outcome.
    pub outcome: ManifoldHostManifestAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldHostManifestAuthorityReview,
}

impl ManifoldHostManifestAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.host_manifest_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.host_id != snapshot.host_manifest.host_id
            || self.host_id != self.review.host_id
            || self.host_id != self.review.audit_event.host_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostIdMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.clock_snapshot != snapshot.clock_snapshot
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                    || applied.active_stream_subscriptions != snapshot.active_stream_subscriptions
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::HostManifestMismatch,
                    ));
                }

                if applied.host_manifest
                    != self.review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.host_manifest.host_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::HostManifestMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldHostManifestAuthorityApplicationOutcome::HostManifestApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

impl ManifoldHostManifestAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent host manifest acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.host_manifest_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.host_id != snapshot.host_manifest.host_id
            || self.host_id != self.request.proposed_manifest.host_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.host_id.to_string(),
                ManifoldAuthorityValidationErrorKind::HostIdMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldHostManifestAuthorityAuditEventKind::HostManifestAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldHostManifestAuthorityAuditEventKind::HostManifestRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let snapshot_lease = self
            .request
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.request.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let Some(snapshot_lease) = snapshot_lease else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownLease,
                ));
            };

            if snapshot_lease != recorded_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        let expected_decision =
            snapshot.host_manifest_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let HostManifestAuthorityDecision::Accepted(expected_manifest) = &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    HostManifestAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    HostManifestAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_host_manifest_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_manifest {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.host_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::HostManifestMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let HostManifestAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_authority_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

/// Audit event for one clock snapshot authority decision.
///
/// The event carries the clock snapshot change request plus exactly one
/// accepted snapshot or rejected result. It records enough authority context
/// for deterministic validation without reading or mutating a live clock.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotAuthorityAuditEvent {
    /// Schema identifier for this audit event.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable event id.
    pub event_id: DottedId,
    /// Authority that made the decision.
    pub authority_id: DottedId,
    /// Authority revision observed before the decision.
    pub prior_authority_revision: Revision,
    /// Accepted clock snapshot observed before the decision.
    pub prior_clock_snapshot: ManifoldClockSnapshot,
    /// Event kind.
    pub event_kind: ManifoldClockSnapshotAuthorityAuditEventKind,
    /// Clock snapshot change request reviewed by authority.
    pub request: ManifoldClockSnapshotChangeRequest,
    /// Accepted clock snapshot. Present only for accepted events.
    pub accepted: Option<ManifoldClockSnapshot>,
    /// Rejected clock snapshot result. Present only for rejected events.
    pub rejection: Option<ManifoldClockSnapshotRejection>,
    /// Lease recorded with the decision, when a lease was presented.
    pub lease: Option<ManifoldControlLease>,
    /// Clock snapshot recorded with the decision.
    pub recorded_clock: ManifoldClockSnapshot,
    /// Stable ids for fixtures, scorecards, or logs backing the event.
    pub evidence_refs: Vec<DottedId>,
}

/// Deterministic review result for one clock snapshot authority decision.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotAuthorityReview {
    /// Schema identifier for this review.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Authority that reviewed the clock snapshot change.
    pub authority_id: DottedId,
    /// Authority revision used by this review.
    pub authority_revision: Revision,
    /// Clock domain used by this review.
    pub clock_domain: DottedId,
    /// Clock epoch used by this review.
    pub clock_epoch_id: DottedId,
    /// Clock sequence used by this review.
    pub clock_sequence: u64,
    /// Review outcome.
    pub outcome: ManifoldClockSnapshotAuthorityReviewOutcome,
    /// Accepted clock snapshot. Present only for accepted reviews.
    pub accepted: Option<ManifoldClockSnapshot>,
    /// Rejected clock snapshot result. Present only for rejected reviews.
    pub rejection: Option<ManifoldClockSnapshotRejection>,
    /// Audit event for the same clock snapshot decision.
    pub audit_event: ManifoldClockSnapshotAuthorityAuditEvent,
}

impl ManifoldClockSnapshotAuthorityReview {
    /// Validates that this review matches the supplied authority snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when review fields and the
    /// nested audit event disagree, or when the event is not valid for the snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.clock_snapshot_review.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.audit_event.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.authority_revision != snapshot.authority_revision
            || self.authority_revision != self.audit_event.prior_authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.clock_domain != self.audit_event.prior_clock_snapshot.clock_domain
            || self.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.clock_epoch_id != self.audit_event.prior_clock_snapshot.clock_epoch_id
            || self.clock_sequence != snapshot.clock_snapshot.sequence
            || self.clock_sequence != self.audit_event.prior_clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        match self.outcome {
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.review_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        if self.accepted != self.audit_event.accepted
            || self.rejection != self.audit_event.rejection
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        if ManifoldClockSnapshotAuthorityAuditEventKind::from(self.outcome)
            != self.audit_event.event_kind
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.review_id.clone(),
                self.audit_event.event_id.to_string(),
                ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
            ));
        }

        self.audit_event.validate_against_snapshot(snapshot)
    }
}

/// Deterministic application result for one clock snapshot authority review.
///
/// This records the bridge from review-time clock authority to accepted
/// authority state without reading live time, mutating host time, or owning a
/// platform clock adapter.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldClockSnapshotAuthorityApplication {
    /// Schema identifier for this application receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable application id.
    pub application_id: DottedId,
    /// Authority that attempted the application.
    pub authority_id: DottedId,
    /// Authority revision before applying the review.
    pub from_authority_revision: Revision,
    /// Clock epoch before applying the review.
    pub from_clock_epoch_id: DottedId,
    /// Clock sequence before applying the review.
    pub from_clock_sequence: u64,
    /// Application outcome.
    pub outcome: ManifoldClockSnapshotAuthorityApplicationOutcome,
    /// Next accepted authority snapshot. Present only for applied outcomes.
    pub applied_snapshot: Option<ManifoldAuthoritySnapshot>,
    /// Rejection. Present only for rejected application outcomes.
    pub rejection: Option<ManifoldAuthoritySnapshotApplicationRejection>,
    /// Review that was applied or rejected for application.
    pub review: ManifoldClockSnapshotAuthorityReview,
}

impl ManifoldClockSnapshotAuthorityApplication {
    /// Validates that this application receipt matches the supplied prior snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the receipt does not
    /// represent a deterministic state transition or deterministic application
    /// rejection for the supplied prior authority snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.clock_snapshot_application.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.authority_id != snapshot.authority_id
            || self.authority_id != self.review.authority_id
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.from_authority_revision != snapshot.authority_revision
            || self.from_authority_revision != self.review.authority_revision
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.from_clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.from_clock_epoch_id != self.review.clock_epoch_id
            || self.from_clock_sequence != snapshot.clock_snapshot.sequence
            || self.from_clock_sequence != self.review.clock_sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.application_id.clone(),
                self.from_clock_epoch_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        self.review.validate_against_snapshot(snapshot)?;

        match self.outcome {
            ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplied => {
                if self.applied_snapshot.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "applied_snapshot".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                if self.review.outcome
                    != ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        self.review.review_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let applied = self
                    .applied_snapshot
                    .as_ref()
                    .expect("applied snapshot presence checked");
                let expected_authority_revision =
                    snapshot.authority_revision.next().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            snapshot.authority_revision.get().to_string(),
                            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                        )
                    })?;

                if applied.authority_revision != expected_authority_revision {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    ));
                }

                if applied.authority_id != snapshot.authority_id
                    || applied.host_manifest != snapshot.host_manifest
                    || applied.stream_registry != snapshot.stream_registry
                    || applied.module_runtime_states != snapshot.module_runtime_states
                    || applied.command_ids != snapshot.command_ids
                    || applied.command_descriptors != snapshot.command_descriptors
                    || applied.active_leases != snapshot.active_leases
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.authority_id.to_string(),
                        ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
                    ));
                }

                if applied.clock_snapshot
                    != self.review.accepted.clone().ok_or_else(|| {
                        ManifoldAuthorityValidationError::new(
                            self.application_id.clone(),
                            "accepted".to_owned(),
                            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                        )
                    })?
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        applied.clock_snapshot.clock_domain.to_string(),
                        ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
                    ));
                }

                applied.validate_authority_links()
            }
            ManifoldClockSnapshotAuthorityApplicationOutcome::ClockSnapshotApplicationRejected => {
                if self.applied_snapshot.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }

                let rejection = self
                    .rejection
                    .as_ref()
                    .expect("application rejection presence checked");
                if rejection.schema_id.as_str()
                    != "rusty.manifold.authority.snapshot_application_rejection.v1"
                    || rejection.application_id != self.application_id
                    || rejection.current_authority_revision != snapshot.authority_revision
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                if self.review.outcome
                    == ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected
                    && rejection.rejection_code.as_str() != "review_rejected"
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.application_id.clone(),
                        rejection.rejection_code.to_string(),
                        ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                    ));
                }

                Ok(())
            }
        }
    }
}

impl ManifoldClockSnapshotAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent clock snapshot acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.clock_snapshot_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.prior_clock_snapshot != snapshot.clock_snapshot {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_clock_snapshot.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldClockSnapshotAuthorityAuditEventKind::ClockSnapshotAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldClockSnapshotAuthorityAuditEventKind::ClockSnapshotRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let snapshot_lease = self
            .request
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.request.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let Some(snapshot_lease) = snapshot_lease else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownLease,
                ));
            };

            if snapshot_lease != recorded_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        let expected_decision =
            snapshot.clock_snapshot_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let ClockSnapshotAuthorityDecision::Accepted(expected_snapshot) = &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    ClockSnapshotAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    ClockSnapshotAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_clock_snapshot_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_snapshot {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.clock_domain.to_string(),
                    ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let ClockSnapshotAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_clock_epoch_id != self.prior_clock_snapshot.clock_epoch_id
                || rejection.current_clock_sequence != self.prior_clock_snapshot.sequence
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_clock_epoch_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

impl ManifoldModuleRuntimeStateAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent runtime-state acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.module_runtime_state_audit_event.v1"
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.module_id != self.request.module_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.module_id.to_string(),
                ManifoldAuthorityValidationErrorKind::ModuleIdMismatch,
            ));
        }

        let snapshot_runtime_revision = snapshot
            .module_runtime_state(&self.module_id)
            .map(|state| state.runtime_revision);
        if self.prior_runtime_revision != snapshot_runtime_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_runtime_revision
                    .map(|revision| revision.get().to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldModuleRuntimeStateAuthorityAuditEventKind::RuntimeStateAccepted => {
                if self.accepted.is_none() || self.transition.is_none() || self.rejection.is_some()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldModuleRuntimeStateAuthorityAuditEventKind::RuntimeStateRejected => {
                if self.accepted.is_some() || self.transition.is_some() || self.rejection.is_none()
                {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let snapshot_lease = self
            .request
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.request.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let Some(snapshot_lease) = snapshot_lease else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownLease,
                ));
            };

            if snapshot_lease != recorded_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        let expected_decision =
            snapshot.module_runtime_state_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let ModuleRuntimeStateAuthorityDecision::Accepted { state, transition } =
                &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    ModuleRuntimeStateAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    ModuleRuntimeStateAuthorityDecision::Accepted { .. } => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_module_runtime_rejection_code(&rejected_value),
                ));
            };

            if accepted != state {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.module_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                ));
            }

            if self.transition.as_ref() != Some(transition) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.module_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let ModuleRuntimeStateAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
                current_runtime_revision,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_runtime_revision != *current_runtime_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection
                        .current_runtime_revision
                        .map(|revision| revision.get().to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

impl ManifoldStreamRegistryAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent registry acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.stream_registry_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.prior_registry_revision != snapshot.stream_registry.registry_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_registry_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldStreamRegistryAuthorityAuditEventKind::RegistryAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldStreamRegistryAuthorityAuditEventKind::RegistryRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let snapshot_lease = self
            .request
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.request.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let Some(snapshot_lease) = snapshot_lease else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownLease,
                ));
            };

            if snapshot_lease != recorded_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        let expected_decision =
            snapshot.stream_registry_authority_decision(&self.request, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            let StreamRegistryAuthorityDecision::Accepted(expected_snapshot) = &expected_decision
            else {
                let rejected_value = match &expected_decision {
                    StreamRegistryAuthorityDecision::Rejected { rejection_code, .. } => {
                        rejection_code.clone()
                    }
                    StreamRegistryAuthorityDecision::Accepted(_) => "accepted".to_owned(),
                };
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejected_value.clone(),
                    authority_error_kind_for_stream_registry_rejection_code(&rejected_value),
                ));
            };

            if accepted != expected_snapshot {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RegistryMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let StreamRegistryAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.request.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.request.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_authority_revision != self.prior_authority_revision
                || rejection.current_registry_revision != self.prior_registry_revision
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.current_registry_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
}

impl ManifoldCommandAuthorityAuditEvent {
    /// Validates this event against the authority snapshot it claims to use.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldAuthorityValidationError`] when the event is not a
    /// consistent command acceptance or rejection for the supplied snapshot.
    pub fn validate_against_snapshot(
        &self,
        snapshot: &ManifoldAuthoritySnapshot,
    ) -> Result<(), ManifoldAuthorityValidationError> {
        if self.schema_id.as_str() != "rusty.manifold.authority.command_audit_event.v1" {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.schema_id.to_string(),
                ManifoldAuthorityValidationErrorKind::UnsupportedSchema,
            ));
        }

        snapshot.validate_authority_links()?;

        if self.authority_id != snapshot.authority_id {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.authority_id.to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
            ));
        }

        if self.prior_authority_revision != snapshot.authority_revision {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.prior_authority_revision.get().to_string(),
                ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch,
            ));
        }

        if self.recorded_clock.clock_domain != snapshot.clock_snapshot.clock_domain
            || self.recorded_clock.clock_epoch_id != snapshot.clock_snapshot.clock_epoch_id
            || self.recorded_clock.sequence < snapshot.clock_snapshot.sequence
        {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                self.recorded_clock.clock_domain.to_string(),
                ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch,
            ));
        }

        if self.evidence_refs.is_empty() {
            return Err(ManifoldAuthorityValidationError::new(
                self.event_id.clone(),
                "evidence_refs".to_owned(),
                ManifoldAuthorityValidationErrorKind::MissingEvidence,
            ));
        }

        match self.event_kind {
            ManifoldCommandAuthorityAuditEventKind::CommandAccepted => {
                if self.accepted.is_none() || self.rejection.is_some() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "accepted".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
            ManifoldCommandAuthorityAuditEventKind::CommandRejected => {
                if self.accepted.is_some() || self.rejection.is_none() {
                    return Err(ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        "rejection".to_owned(),
                        ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                    ));
                }
            }
        }

        let snapshot_lease = self
            .envelope
            .lease_id
            .as_ref()
            .and_then(|id| snapshot.active_lease(id));
        if let Some(recorded_lease) = &self.lease {
            if self.envelope.lease_id.as_ref() != Some(&recorded_lease.lease_id) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }

            let Some(snapshot_lease) = snapshot_lease else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::UnknownLease,
                ));
            };

            if snapshot_lease != recorded_lease {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    recorded_lease.lease_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        let expected_decision =
            snapshot.command_authority_decision(&self.envelope, &self.recorded_clock);

        if let Some(accepted) = &self.accepted {
            if let CommandAuthorityDecision::Rejected { rejection_code, .. } = &expected_decision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    (*rejection_code).to_owned(),
                    authority_error_kind_for_rejection_code(rejection_code),
                ));
            }

            if accepted.request_id != self.envelope.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if accepted.authority_id != self.authority_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.authority_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch,
                ));
            }

            let expected_accepted_revision =
                self.prior_authority_revision.next().ok_or_else(|| {
                    ManifoldAuthorityValidationError::new(
                        self.event_id.clone(),
                        self.prior_authority_revision.get().to_string(),
                        ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                    )
                })?;
            if accepted.accepted_revision != expected_accepted_revision {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    accepted.accepted_revision.get().to_string(),
                    ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch,
                ));
            }

            if accepted.lease_id != self.envelope.lease_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    "accepted.lease_id".to_owned(),
                    ManifoldAuthorityValidationErrorKind::LeaseMismatch,
                ));
            }
        }

        if let Some(rejection) = &self.rejection {
            let CommandAuthorityDecision::Rejected {
                rejection_code,
                message,
                retryable,
            } = &expected_decision
            else {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    self.envelope.command_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch,
                ));
            };

            if rejection.request_id != self.envelope.request_id {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.request_id.to_string(),
                    ManifoldAuthorityValidationErrorKind::RequestIdMismatch,
                ));
            }

            if rejection.current_revision != Some(self.prior_authority_revision) {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection
                        .current_revision
                        .map(|revision| revision.get().to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch,
                ));
            }

            if rejection.rejection_code.as_str() != *rejection_code
                || rejection.message != *message
                || rejection.retryable != *retryable
            {
                return Err(ManifoldAuthorityValidationError::new(
                    self.event_id.clone(),
                    rejection.rejection_code.to_string(),
                    ManifoldAuthorityValidationErrorKind::RejectionMismatch,
                ));
            }
        }

        Ok(())
    }
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

/// Descriptor handed to an operator or render shell for one contract-backed run.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldShellHandoffManifest {
    /// Schema identifier for this handoff.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable handoff id.
    pub handoff_id: DottedId,
    /// Handoff revision.
    pub handoff_revision: Revision,
    /// Target host profile, such as desktop, mobile, or headset.
    pub target_host_profile: DottedId,
    /// Target shell app id.
    pub shell_app_id: DottedId,
    /// Validation slot this shell handoff is expected to run.
    pub validation_slot_id: DottedId,
    /// Stream bindings the shell must publish or subscribe to.
    pub stream_bindings: Vec<ManifoldShellStreamBinding>,
    /// Commands the shell may request through Manifold authority.
    pub command_ids: Vec<DottedId>,
    /// Transport offers used by the shell for this handoff.
    pub transport_offers: Vec<TransportOffer>,
    /// Scorecard expected from this shell handoff.
    pub expected_scorecard_id: DottedId,
}

impl ManifoldShellHandoffManifest {
    /// Validates stream, command, endpoint, and validation-slot references.
    ///
    /// # Errors
    ///
    /// Returns [`ShellHandoffValidationError`] when the handoff references a
    /// stream, command, endpoint, or validation slot that is not known to the
    /// selected bundle context.
    pub fn validate_links(
        &self,
        stream_registry: &ManifoldStreamRegistrySnapshot,
        command_ids: &[DottedId],
        endpoint_ids: &[DottedId],
        validation_slot_ids: &[DottedId],
    ) -> Result<(), ShellHandoffValidationError> {
        if !validation_slot_ids
            .iter()
            .any(|slot_id| slot_id == &self.validation_slot_id)
        {
            return Err(ShellHandoffValidationError::new(
                self.handoff_id.clone(),
                self.validation_slot_id.clone(),
                ShellHandoffValidationErrorKind::UnknownValidationSlot,
            ));
        }

        for binding in &self.stream_bindings {
            if !stream_registry
                .streams
                .iter()
                .any(|stream| stream.stream_id == binding.stream_id)
            {
                return Err(ShellHandoffValidationError::new(
                    self.handoff_id.clone(),
                    binding.stream_id.clone(),
                    ShellHandoffValidationErrorKind::UnknownStream,
                ));
            }
        }

        for command_id in &self.command_ids {
            if !command_ids.iter().any(|known| known == command_id) {
                return Err(ShellHandoffValidationError::new(
                    self.handoff_id.clone(),
                    command_id.clone(),
                    ShellHandoffValidationErrorKind::UnknownCommand,
                ));
            }
        }

        for offer in &self.transport_offers {
            if let Some(endpoint_id) = &offer.endpoint_id {
                if !endpoint_ids.iter().any(|known| known == endpoint_id) {
                    return Err(ShellHandoffValidationError::new(
                        self.handoff_id.clone(),
                        endpoint_id.clone(),
                        ShellHandoffValidationErrorKind::UnknownEndpoint,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Builds a deterministic Manifold authority review receipt for this handoff.
    ///
    /// The receipt reviews links only. It does not launch a shell, open a
    /// command session, use a platform runtime, or depend on a legacy app.
    #[must_use]
    pub fn review_receipt(
        &self,
        stream_registry: &ManifoldStreamRegistrySnapshot,
        command_ids: &[DottedId],
        endpoint_ids: &[DottedId],
        validation_slot_ids: &[DottedId],
    ) -> ManifoldShellHandoffReviewReceipt {
        let validation_slot_known = validation_slot_ids
            .iter()
            .any(|slot_id| slot_id == &self.validation_slot_id);
        let streams_known = self.stream_bindings.iter().all(|binding| {
            stream_registry
                .streams
                .iter()
                .any(|stream| stream.stream_id == binding.stream_id)
        });
        let commands_known = self
            .command_ids
            .iter()
            .all(|command_id| command_ids.iter().any(|known| known == command_id));
        let endpoints_known = self.transport_offers.iter().all(|offer| {
            offer.endpoint_id.as_ref().map_or(true, |endpoint_id| {
                endpoint_ids.iter().any(|known| known == endpoint_id)
            })
        });
        let no_runtime_started = true;
        let checks = vec![
            shell_handoff_review_check(
                "check.shell_handoff.validation_slot",
                validation_slot_known,
                "shell handoff validation slot resolves",
                "shell handoff validation slot is unknown",
                "issue.shell_handoff.unknown_validation_slot",
            ),
            shell_handoff_review_check(
                "check.shell_handoff.streams",
                streams_known,
                "shell handoff stream bindings resolve",
                "shell handoff references an unknown stream",
                "issue.shell_handoff.unknown_stream",
            ),
            shell_handoff_review_check(
                "check.shell_handoff.commands",
                commands_known,
                "shell handoff command ids resolve",
                "shell handoff references an unknown command",
                "issue.shell_handoff.unknown_command",
            ),
            shell_handoff_review_check(
                "check.shell_handoff.endpoints",
                endpoints_known,
                "shell handoff transport endpoints resolve",
                "shell handoff references an unknown endpoint",
                "issue.shell_handoff.unknown_endpoint",
            ),
            shell_handoff_review_check(
                "check.shell_handoff.no_runtime_started",
                no_runtime_started,
                "shell handoff review performed no runtime, launch, or session work",
                "shell handoff review started runtime, launch, or session work",
                "issue.shell_handoff.runtime_started",
            ),
        ];
        let issues = checks
            .iter()
            .flat_map(|check| check.issue_codes.iter().cloned())
            .map(shell_handoff_review_issue)
            .collect::<Vec<_>>();

        ManifoldShellHandoffReviewReceipt {
            schema_id: shell_handoff_review_schema_id(),
            review_id: shell_handoff_review_id(&self.handoff_id),
            handoff_id: self.handoff_id.clone(),
            handoff_revision: self.handoff_revision,
            target_host_profile: self.target_host_profile.clone(),
            shell_app_id: self.shell_app_id.clone(),
            validation_slot_id: self.validation_slot_id.clone(),
            status: if issues.is_empty() {
                ValidationStatus::Pass
            } else {
                ValidationStatus::Fail
            },
            manifold_authority: manifold_authority_id(),
            reviewed_stream_ids: self
                .stream_bindings
                .iter()
                .map(|binding| binding.stream_id.clone())
                .collect(),
            reviewed_command_ids: self.command_ids.clone(),
            reviewed_transport_ids: self
                .transport_offers
                .iter()
                .map(|offer| offer.transport_id.clone())
                .collect(),
            reviewed_endpoint_ids: self
                .transport_offers
                .iter()
                .filter_map(|offer| offer.endpoint_id.clone())
                .collect(),
            runtime_execution_performed: false,
            platform_execution_performed: false,
            launch_started: false,
            command_session_started: false,
            legacy_app_dependency_used: false,
            checks,
            issues,
        }
    }
}

/// One shell stream binding inside a handoff manifest.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldShellStreamBinding {
    /// Stream id bound to the shell.
    pub stream_id: DottedId,
    /// Direction from the shell's point of view.
    pub direction: ShellStreamDirection,
    /// Role this stream plays in the shell workflow.
    pub role: DottedId,
    /// Whether the handoff cannot run without this stream.
    pub required: bool,
}

/// Manifold authority review of one shell handoff descriptor.
#[allow(clippy::struct_excessive_bools)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldShellHandoffReviewReceipt {
    /// Schema identifier for this review receipt.
    #[cfg_attr(feature = "serde", serde(rename = "$schema"))]
    pub schema_id: SchemaId,
    /// Stable review id.
    pub review_id: DottedId,
    /// Reviewed shell handoff id.
    pub handoff_id: DottedId,
    /// Reviewed shell handoff revision.
    pub handoff_revision: Revision,
    /// Target host profile from the reviewed handoff.
    pub target_host_profile: DottedId,
    /// Target shell app id from the reviewed handoff.
    pub shell_app_id: DottedId,
    /// Validation slot from the reviewed handoff.
    pub validation_slot_id: DottedId,
    /// Review status.
    pub status: ValidationStatus,
    /// Manifold authority responsible for accepting or rejecting this review.
    pub manifold_authority: DottedId,
    /// Stream ids reviewed from the handoff.
    pub reviewed_stream_ids: Vec<DottedId>,
    /// Command ids reviewed from the handoff.
    pub reviewed_command_ids: Vec<DottedId>,
    /// Transport ids reviewed from the handoff.
    pub reviewed_transport_ids: Vec<DottedId>,
    /// Endpoint ids reviewed from endpoint-bound transport offers.
    pub reviewed_endpoint_ids: Vec<DottedId>,
    /// Whether review executed runtime code.
    pub runtime_execution_performed: bool,
    /// Whether review executed platform code.
    pub platform_execution_performed: bool,
    /// Whether review launched a shell.
    pub launch_started: bool,
    /// Whether review opened a command session.
    pub command_session_started: bool,
    /// Whether review depended on a legacy app implementation.
    pub legacy_app_dependency_used: bool,
    /// Individual review checks.
    pub checks: Vec<ValidationCheck>,
    /// Review issues.
    pub issues: Vec<ManifoldIssue>,
}

impl ManifoldShellHandoffReviewReceipt {
    /// Validates that this receipt still matches the reviewed handoff and is review-only.
    ///
    /// # Errors
    ///
    /// Returns [`ShellHandoffReviewReceiptValidationError`] when the receipt
    /// has drifted from the handoff, claims inconsistent status, or reports
    /// runtime, platform, launch, legacy-app, or command-session side effects.
    pub fn validate_against_handoff(
        &self,
        handoff: &ManifoldShellHandoffManifest,
    ) -> Result<(), ShellHandoffReviewReceiptValidationError> {
        if self.schema_id != shell_handoff_review_schema_id() {
            return Err(ShellHandoffReviewReceiptValidationError::new(
                self.review_id.clone(),
                self.schema_id.to_string(),
                ShellHandoffReviewReceiptValidationErrorKind::UnsupportedSchema,
            ));
        }

        if self.handoff_id != handoff.handoff_id
            || self.handoff_revision != handoff.handoff_revision
            || self.target_host_profile != handoff.target_host_profile
            || self.shell_app_id != handoff.shell_app_id
            || self.validation_slot_id != handoff.validation_slot_id
        {
            return Err(ShellHandoffReviewReceiptValidationError::new(
                self.review_id.clone(),
                self.handoff_id.to_string(),
                ShellHandoffReviewReceiptValidationErrorKind::HandoffMismatch,
            ));
        }

        if self.runtime_execution_performed
            || self.platform_execution_performed
            || self.launch_started
            || self.command_session_started
            || self.legacy_app_dependency_used
        {
            return Err(ShellHandoffReviewReceiptValidationError::new(
                self.review_id.clone(),
                self.handoff_id.to_string(),
                ShellHandoffReviewReceiptValidationErrorKind::RuntimeStarted,
            ));
        }

        let expected_stream_ids = handoff
            .stream_bindings
            .iter()
            .map(|binding| binding.stream_id.clone())
            .collect::<Vec<_>>();
        let expected_transport_ids = handoff
            .transport_offers
            .iter()
            .map(|offer| offer.transport_id.clone())
            .collect::<Vec<_>>();
        let expected_endpoint_ids = handoff
            .transport_offers
            .iter()
            .filter_map(|offer| offer.endpoint_id.clone())
            .collect::<Vec<_>>();
        if self.reviewed_stream_ids != expected_stream_ids
            || self.reviewed_command_ids != handoff.command_ids
            || self.reviewed_transport_ids != expected_transport_ids
            || self.reviewed_endpoint_ids != expected_endpoint_ids
        {
            return Err(ShellHandoffReviewReceiptValidationError::new(
                self.review_id.clone(),
                self.handoff_id.to_string(),
                ShellHandoffReviewReceiptValidationErrorKind::ReviewedIdsMismatch,
            ));
        }

        let failed_checks = self
            .checks
            .iter()
            .filter(|check| check.status == ValidationStatus::Fail)
            .count();
        let status_consistent = match self.status {
            ValidationStatus::Pass => failed_checks == 0 && self.issues.is_empty(),
            ValidationStatus::Fail => failed_checks > 0 && !self.issues.is_empty(),
            ValidationStatus::Warn => false,
        };
        if !status_consistent {
            return Err(ShellHandoffReviewReceiptValidationError::new(
                self.review_id.clone(),
                self.handoff_id.to_string(),
                ShellHandoffReviewReceiptValidationErrorKind::StatusMismatch,
            ));
        }

        Ok(())
    }
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

/// Command authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldCommandAuthorityAuditEventKind {
    /// Authority accepted a command request.
    CommandAccepted,
    /// Authority rejected a command request.
    CommandRejected,
}

/// Stream-registry authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamRegistryAuthorityAuditEventKind {
    /// Authority accepted a registry change request.
    RegistryAccepted,
    /// Authority rejected a registry change request.
    RegistryRejected,
}

/// Stream subscription authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionAuthorityAuditEventKind {
    /// Authority accepted a subscription request.
    SubscriptionAccepted,
    /// Authority rejected a subscription request.
    SubscriptionRejected,
}

/// Stream subscription release authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind {
    /// Authority accepted a subscription release request.
    SubscriptionReleased,
    /// Authority rejected a subscription release request.
    SubscriptionReleaseRejected,
}

/// Stream subscription renewal authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind {
    /// Authority accepted a subscription renewal request.
    SubscriptionRenewed,
    /// Authority rejected a subscription renewal request.
    SubscriptionRenewalRejected,
}

/// Authority expiry sweep audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityExpirySweepAuthorityAuditEventKind {
    /// Authority accepted expired state for removal.
    ExpiredStateAccepted,
    /// Authority rejected an expiry sweep request.
    ExpirySweepRejected,
}

/// Module runtime-state authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldModuleRuntimeStateAuthorityAuditEventKind {
    /// Authority accepted a runtime-state change request.
    RuntimeStateAccepted,
    /// Authority rejected a runtime-state change request.
    RuntimeStateRejected,
}

/// Host manifest authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldHostManifestAuthorityAuditEventKind {
    /// Authority accepted a host manifest change request.
    HostManifestAccepted,
    /// Authority rejected a host manifest change request.
    HostManifestRejected,
}

/// Clock snapshot authority audit event kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldClockSnapshotAuthorityAuditEventKind {
    /// Authority accepted a clock snapshot change request.
    ClockSnapshotAccepted,
    /// Authority rejected a clock snapshot change request.
    ClockSnapshotRejected,
}

/// Command authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldCommandAuthorityReviewOutcome {
    /// Authority accepted the command request.
    CommandAccepted,
    /// Authority rejected the command request.
    CommandRejected,
}

impl From<ManifoldCommandAuthorityReviewOutcome> for ManifoldCommandAuthorityAuditEventKind {
    fn from(outcome: ManifoldCommandAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldCommandAuthorityReviewOutcome::CommandAccepted => Self::CommandAccepted,
            ManifoldCommandAuthorityReviewOutcome::CommandRejected => Self::CommandRejected,
        }
    }
}

/// Stream-registry authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamRegistryAuthorityReviewOutcome {
    /// Authority accepted the registry change request.
    RegistryAccepted,
    /// Authority rejected the registry change request.
    RegistryRejected,
}

impl From<ManifoldStreamRegistryAuthorityReviewOutcome>
    for ManifoldStreamRegistryAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamRegistryAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryAccepted => {
                Self::RegistryAccepted
            }
            ManifoldStreamRegistryAuthorityReviewOutcome::RegistryRejected => {
                Self::RegistryRejected
            }
        }
    }
}

/// Stream-registry authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamRegistryAuthorityApplicationOutcome {
    /// Accepted stream-registry review was applied to the authority snapshot.
    RegistrySnapshotApplied,
    /// Stream-registry review could not be applied to accepted authority state.
    RegistryApplicationRejected,
}

/// Stream subscription authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionAuthorityReviewOutcome {
    /// Authority accepted the subscription request.
    SubscriptionAccepted,
    /// Authority rejected the subscription request.
    SubscriptionRejected,
}

impl From<ManifoldStreamSubscriptionAuthorityReviewOutcome>
    for ManifoldStreamSubscriptionAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamSubscriptionAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionAccepted => {
                Self::SubscriptionAccepted
            }
            ManifoldStreamSubscriptionAuthorityReviewOutcome::SubscriptionRejected => {
                Self::SubscriptionRejected
            }
        }
    }
}

/// Stream subscription authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionAuthorityApplicationOutcome {
    /// Accepted stream subscription review was applied to the authority snapshot.
    SubscriptionApplied,
    /// Stream subscription review could not be applied to accepted authority state.
    SubscriptionApplicationRejected,
}

/// Stream subscription release authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome {
    /// Authority accepted the subscription release request.
    SubscriptionReleased,
    /// Authority rejected the subscription release request.
    SubscriptionReleaseRejected,
}

impl From<ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome>
    for ManifoldStreamSubscriptionReleaseAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleased => {
                Self::SubscriptionReleased
            }
            ManifoldStreamSubscriptionReleaseAuthorityReviewOutcome::SubscriptionReleaseRejected => {
                Self::SubscriptionReleaseRejected
            }
        }
    }
}

/// Stream subscription release authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionReleaseAuthorityApplicationOutcome {
    /// Accepted stream subscription release review was applied to the authority snapshot.
    SubscriptionReleaseApplied,
    /// Stream subscription release review could not be applied to accepted authority state.
    SubscriptionReleaseApplicationRejected,
}

/// Stream subscription renewal authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome {
    /// Authority accepted the subscription renewal request.
    SubscriptionRenewed,
    /// Authority rejected the subscription renewal request.
    SubscriptionRenewalRejected,
}

impl From<ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome>
    for ManifoldStreamSubscriptionRenewalAuthorityAuditEventKind
{
    fn from(outcome: ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewed => {
                Self::SubscriptionRenewed
            }
            ManifoldStreamSubscriptionRenewalAuthorityReviewOutcome::SubscriptionRenewalRejected => {
                Self::SubscriptionRenewalRejected
            }
        }
    }
}

/// Stream subscription renewal authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionRenewalAuthorityApplicationOutcome {
    /// Accepted stream subscription renewal review was applied to the authority snapshot.
    SubscriptionRenewalApplied,
    /// Stream subscription renewal review could not be applied to accepted authority state.
    SubscriptionRenewalApplicationRejected,
}

/// Authority expiry sweep review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityExpirySweepAuthorityReviewOutcome {
    /// Authority accepted expired state for removal.
    ExpiredStateAccepted,
    /// Authority rejected the expiry sweep request.
    ExpirySweepRejected,
}

impl From<ManifoldAuthorityExpirySweepAuthorityReviewOutcome>
    for ManifoldAuthorityExpirySweepAuthorityAuditEventKind
{
    fn from(outcome: ManifoldAuthorityExpirySweepAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpiredStateAccepted => {
                Self::ExpiredStateAccepted
            }
            ManifoldAuthorityExpirySweepAuthorityReviewOutcome::ExpirySweepRejected => {
                Self::ExpirySweepRejected
            }
        }
    }
}

/// Authority expiry sweep application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityExpirySweepAuthorityApplicationOutcome {
    /// Accepted expiry sweep review was applied to the authority snapshot.
    ExpiredStateApplied,
    /// Expiry sweep review could not be applied to accepted authority state.
    ExpirySweepApplicationRejected,
}

/// Stream subscriber kind.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriberKind {
    /// UI or dashboard subscriber.
    Ui,
    /// Runtime module subscriber.
    Runtime,
    /// Agent or CLI subscriber.
    Agent,
}

/// Accepted stream subscription state.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldStreamSubscriptionState {
    /// Subscription is active and counts against the stream limit.
    Active,
    /// Subscription was released by the subscriber or authority.
    Released,
    /// Subscription expired by TTL.
    Expired,
}

/// Module runtime-state authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldModuleRuntimeStateAuthorityApplicationOutcome {
    /// Accepted runtime-state review was applied to the authority snapshot.
    RuntimeStateApplied,
    /// Runtime-state review could not be applied to accepted authority state.
    RuntimeStateApplicationRejected,
}

/// Module runtime-state authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldModuleRuntimeStateAuthorityReviewOutcome {
    /// Authority accepted the runtime-state change request.
    RuntimeStateAccepted,
    /// Authority rejected the runtime-state change request.
    RuntimeStateRejected,
}

impl From<ManifoldModuleRuntimeStateAuthorityReviewOutcome>
    for ManifoldModuleRuntimeStateAuthorityAuditEventKind
{
    fn from(outcome: ManifoldModuleRuntimeStateAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateAccepted => {
                Self::RuntimeStateAccepted
            }
            ManifoldModuleRuntimeStateAuthorityReviewOutcome::RuntimeStateRejected => {
                Self::RuntimeStateRejected
            }
        }
    }
}

/// Host manifest authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldHostManifestAuthorityReviewOutcome {
    /// Authority accepted the host manifest change request.
    HostManifestAccepted,
    /// Authority rejected the host manifest change request.
    HostManifestRejected,
}

/// Host manifest authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldHostManifestAuthorityApplicationOutcome {
    /// Accepted host manifest review was applied to the authority snapshot.
    HostManifestApplied,
    /// Host manifest review could not be applied to accepted authority state.
    HostManifestApplicationRejected,
}

impl From<ManifoldHostManifestAuthorityReviewOutcome>
    for ManifoldHostManifestAuthorityAuditEventKind
{
    fn from(outcome: ManifoldHostManifestAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestAccepted => {
                Self::HostManifestAccepted
            }
            ManifoldHostManifestAuthorityReviewOutcome::HostManifestRejected => {
                Self::HostManifestRejected
            }
        }
    }
}

/// Clock snapshot authority review outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldClockSnapshotAuthorityReviewOutcome {
    /// Authority accepted the clock snapshot change request.
    ClockSnapshotAccepted,
    /// Authority rejected the clock snapshot change request.
    ClockSnapshotRejected,
}

/// Clock snapshot authority application outcome.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldClockSnapshotAuthorityApplicationOutcome {
    /// Accepted clock snapshot review was applied to the authority snapshot.
    ClockSnapshotApplied,
    /// Clock snapshot review could not be applied to accepted authority state.
    ClockSnapshotApplicationRejected,
}

impl From<ManifoldClockSnapshotAuthorityReviewOutcome>
    for ManifoldClockSnapshotAuthorityAuditEventKind
{
    fn from(outcome: ManifoldClockSnapshotAuthorityReviewOutcome) -> Self {
        match outcome {
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotAccepted => {
                Self::ClockSnapshotAccepted
            }
            ManifoldClockSnapshotAuthorityReviewOutcome::ClockSnapshotRejected => {
                Self::ClockSnapshotRejected
            }
        }
    }
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

/// Direction of a stream binding from an operator or render shell's point of view.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellStreamDirection {
    /// The shell publishes this stream to Manifold.
    Publish,
    /// The shell subscribes to this stream from Manifold.
    Subscribe,
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
    rejected_id: DottedId,
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
        &self.rejected_id
    }

    /// Returns the rejected module or endpoint id.
    #[must_use]
    pub fn rejected_id(&self) -> &DottedId {
        &self.rejected_id
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
            StreamRegistryValidationErrorKind::UnknownTransportEndpoint => {
                "unknown_transport_endpoint"
            }
        }
    }
}

impl fmt::Display for StreamRegistryValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "stream {} contains invalid reference {}: {:?}",
            self.stream_id, self.rejected_id, self.kind
        )
    }
}

impl std::error::Error for StreamRegistryValidationError {}

/// Stream registry validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRegistryValidationErrorKind {
    /// A stream references a source module that is not known to the registry.
    UnknownModuleLink,
    /// A transport offer references an endpoint not advertised by the host.
    UnknownTransportEndpoint,
}

/// Authority snapshot or command audit validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldAuthorityValidationError {
    subject_id: DottedId,
    rejected_value: String,
    kind: ManifoldAuthorityValidationErrorKind,
}

impl ManifoldAuthorityValidationError {
    fn new(
        subject_id: DottedId,
        rejected_value: String,
        kind: ManifoldAuthorityValidationErrorKind,
    ) -> Self {
        Self {
            subject_id,
            rejected_value,
            kind,
        }
    }

    /// Returns the affected authority, event, module, command, or lease id.
    #[must_use]
    pub fn subject_id(&self) -> &DottedId {
        &self.subject_id
    }

    /// Returns the rejected value.
    #[must_use]
    pub fn rejected_value(&self) -> &str {
        &self.rejected_value
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> ManifoldAuthorityValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            ManifoldAuthorityValidationErrorKind::UnsupportedSchema => "unsupported_schema",
            ManifoldAuthorityValidationErrorKind::HostHasNoAuthority => "host_has_no_authority",
            ManifoldAuthorityValidationErrorKind::HostEndpointSecurityMismatch => {
                "host_endpoint_security_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::HostIdMismatch => "host_id_mismatch",
            ManifoldAuthorityValidationErrorKind::HostManifestMismatch => "host_manifest_mismatch",
            ManifoldAuthorityValidationErrorKind::HostManifestValidationFailed => {
                "host_manifest_validation_failed"
            }
            ManifoldAuthorityValidationErrorKind::HostEndpointInUse => "host_endpoint_in_use",
            ManifoldAuthorityValidationErrorKind::HostCapabilityInUse => "host_capability_in_use",
            ManifoldAuthorityValidationErrorKind::HostBackendInUse => "host_backend_in_use",
            ManifoldAuthorityValidationErrorKind::ClockDomainMismatch => "clock_domain_mismatch",
            ManifoldAuthorityValidationErrorKind::ClockSnapshotMismatch => {
                "clock_snapshot_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::RegistryRevisionAhead => {
                "registry_revision_ahead"
            }
            ManifoldAuthorityValidationErrorKind::RegistryRevisionMismatch => {
                "registry_revision_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::RegistryMismatch => "registry_mismatch",
            ManifoldAuthorityValidationErrorKind::UnknownStreamModule => "unknown_stream_module",
            ManifoldAuthorityValidationErrorKind::UnknownModuleStream => "unknown_module_stream",
            ManifoldAuthorityValidationErrorKind::UnknownModuleCommand => "unknown_module_command",
            ManifoldAuthorityValidationErrorKind::UnknownModule => "unknown_module",
            ManifoldAuthorityValidationErrorKind::ModuleIdMismatch => "module_id_mismatch",
            ManifoldAuthorityValidationErrorKind::RuntimeRevisionMismatch => {
                "runtime_revision_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::ModuleRuntimeMismatch => {
                "module_runtime_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::ModuleRuntimeValidationFailed => {
                "module_runtime_validation_failed"
            }
            ManifoldAuthorityValidationErrorKind::UnknownCommand => "unknown_command",
            ManifoldAuthorityValidationErrorKind::CapabilityNotAdvertised => {
                "capability_not_advertised"
            }
            ManifoldAuthorityValidationErrorKind::InactiveLease => "inactive_lease",
            ManifoldAuthorityValidationErrorKind::LeaseRevisionAhead => "lease_revision_ahead",
            ManifoldAuthorityValidationErrorKind::UnknownLease => "unknown_lease",
            ManifoldAuthorityValidationErrorKind::LeaseScopeBusy => "lease_scope_busy",
            ManifoldAuthorityValidationErrorKind::InvalidLeaseTtl => "invalid_lease_ttl",
            ManifoldAuthorityValidationErrorKind::AuthorityIdMismatch => "authority_id_mismatch",
            ManifoldAuthorityValidationErrorKind::AuthorityRevisionMismatch => {
                "authority_revision_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::DecisionShapeMismatch => {
                "decision_shape_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::RequestIdMismatch => "request_id_mismatch",
            ManifoldAuthorityValidationErrorKind::AcceptanceRevisionMismatch => {
                "acceptance_revision_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::RejectionRevisionMismatch => {
                "rejection_revision_mismatch"
            }
            ManifoldAuthorityValidationErrorKind::RejectionMismatch => "rejection_mismatch",
            ManifoldAuthorityValidationErrorKind::LeaseMismatch => "lease_mismatch",
            ManifoldAuthorityValidationErrorKind::StreamDiffMismatch => "stream_diff_mismatch",
            ManifoldAuthorityValidationErrorKind::StreamRegistryValidationFailed => {
                "stream_registry_validation_failed"
            }
            ManifoldAuthorityValidationErrorKind::UnknownStream => "unknown_stream",
            ManifoldAuthorityValidationErrorKind::UnknownTransport => "unknown_transport",
            ManifoldAuthorityValidationErrorKind::UnknownSubscription => "unknown_subscription",
            ManifoldAuthorityValidationErrorKind::SubscriptionNotAllowed => {
                "subscription_not_allowed"
            }
            ManifoldAuthorityValidationErrorKind::SubscriptionLimitReached => {
                "subscriber_limit_reached"
            }
            ManifoldAuthorityValidationErrorKind::InvalidSubscriptionTtl => {
                "invalid_subscription_ttl"
            }
            ManifoldAuthorityValidationErrorKind::SubscriptionMismatch => "subscription_mismatch",
            ManifoldAuthorityValidationErrorKind::StreamSubscriptionValidationFailed => {
                "stream_subscription_validation_failed"
            }
            ManifoldAuthorityValidationErrorKind::MissingEvidence => "missing_evidence",
            ManifoldAuthorityValidationErrorKind::CommandValidationFailed => {
                "command_validation_failed"
            }
            ManifoldAuthorityValidationErrorKind::LeaseRequestValidationFailed => {
                "lease_request_validation_failed"
            }
        }
    }
}

impl fmt::Display for ManifoldAuthorityValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authority validation {} rejected {}: {:?}",
            self.subject_id, self.rejected_value, self.kind
        )
    }
}

impl std::error::Error for ManifoldAuthorityValidationError {}

/// Authority snapshot or command audit validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldAuthorityValidationErrorKind {
    /// The schema id is not supported by this validator.
    UnsupportedSchema,
    /// The host manifest does not advertise an authority role.
    HostHasNoAuthority,
    /// The nested host manifest contains an unsafe endpoint pairing.
    HostEndpointSecurityMismatch,
    /// Host id changed or event/review host ids disagree.
    HostIdMismatch,
    /// Accepted host manifest does not match deterministic review.
    HostManifestMismatch,
    /// A host manifest proposal fails endpoint, capability, backend, or role validation.
    HostManifestValidationFailed,
    /// A host manifest proposal removes an endpoint still considered in use.
    HostEndpointInUse,
    /// A host manifest proposal removes a capability still considered in use.
    HostCapabilityInUse,
    /// A host manifest proposal removes a backend still considered in use.
    HostBackendInUse,
    /// Host and clock snapshot use different clock domains.
    ClockDomainMismatch,
    /// Event clock does not match the snapshot clock domain, epoch, or sequence.
    ClockSnapshotMismatch,
    /// Stream registry revision is newer than the authority revision.
    RegistryRevisionAhead,
    /// Stream registry revision does not match the reviewed request or event.
    RegistryRevisionMismatch,
    /// Accepted stream registry snapshot does not match deterministic diff application.
    RegistryMismatch,
    /// A stream source module is not present in runtime state.
    UnknownStreamModule,
    /// A module runtime state references an unknown active stream.
    UnknownModuleStream,
    /// A module runtime state references an unknown active command.
    UnknownModuleCommand,
    /// A module runtime-state request targets a module absent from authority state.
    UnknownModule,
    /// Runtime-state request and nested proposed state disagree about the module id.
    ModuleIdMismatch,
    /// Runtime-state request or event uses the wrong runtime revision.
    RuntimeRevisionMismatch,
    /// Accepted runtime-state or transition does not match deterministic review.
    ModuleRuntimeMismatch,
    /// A module runtime-state request fails link, backend, lifecycle, or transition validation.
    ModuleRuntimeValidationFailed,
    /// A command id or descriptor is unknown to the authority.
    UnknownCommand,
    /// A command or lease requires a capability absent from the host.
    CapabilityNotAdvertised,
    /// An active-lease set contains a non-active lease.
    InactiveLease,
    /// A lease was granted after the authority revision being reviewed.
    LeaseRevisionAhead,
    /// A command envelope references a lease absent from the authority snapshot.
    UnknownLease,
    /// A lease request targets a scope that already has an active lease.
    LeaseScopeBusy,
    /// A lease request ttl is invalid.
    InvalidLeaseTtl,
    /// Event and nested result disagree about the authority id.
    AuthorityIdMismatch,
    /// Event prior revision does not match the supplied authority snapshot.
    AuthorityRevisionMismatch,
    /// Accepted/rejected fields do not match the event kind.
    DecisionShapeMismatch,
    /// Accepted or rejected result references the wrong request id.
    RequestIdMismatch,
    /// Accepted result did not advance authority revision.
    AcceptanceRevisionMismatch,
    /// Rejected result does not report the reviewed authority revision.
    RejectionRevisionMismatch,
    /// Rejected result does not match the deterministic rejection code, message, or retryability.
    RejectionMismatch,
    /// Event, envelope, lease, or accepted result disagree about the lease.
    LeaseMismatch,
    /// A stream-registry diff does not match the current registry.
    StreamDiffMismatch,
    /// A stream-registry request fails link, endpoint, or topology validation.
    StreamRegistryValidationFailed,
    /// A stream subscription references a stream absent from the registry.
    UnknownStream,
    /// A stream subscription references an unknown transport offer or endpoint.
    UnknownTransport,
    /// A stream subscription release references an unknown active subscription.
    UnknownSubscription,
    /// A stream subscription is disallowed by stream policy.
    SubscriptionNotAllowed,
    /// A stream subscription would exceed the stream subscriber limit.
    SubscriptionLimitReached,
    /// A stream subscription ttl is invalid.
    InvalidSubscriptionTtl,
    /// A stream subscription event, review, or accepted state is inconsistent.
    SubscriptionMismatch,
    /// A stream subscription request fails admission validation.
    StreamSubscriptionValidationFailed,
    /// The audit event has no backing evidence references.
    MissingEvidence,
    /// The command envelope fails deterministic descriptor/revision/lease validation.
    CommandValidationFailed,
    /// The lease request fails deterministic revision/capability/scope validation.
    LeaseRequestValidationFailed,
}

/// Shell handoff review receipt validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellHandoffReviewReceiptValidationError {
    review_id: DottedId,
    rejected_value: String,
    kind: ShellHandoffReviewReceiptValidationErrorKind,
}

impl ShellHandoffReviewReceiptValidationError {
    fn new(
        review_id: DottedId,
        rejected_value: String,
        kind: ShellHandoffReviewReceiptValidationErrorKind,
    ) -> Self {
        Self {
            review_id,
            rejected_value,
            kind,
        }
    }

    /// Returns the affected shell handoff review id.
    #[must_use]
    pub fn review_id(&self) -> &DottedId {
        &self.review_id
    }

    /// Returns the rejected value.
    #[must_use]
    pub fn rejected_value(&self) -> &str {
        &self.rejected_value
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> ShellHandoffReviewReceiptValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            ShellHandoffReviewReceiptValidationErrorKind::UnsupportedSchema => "unsupported_schema",
            ShellHandoffReviewReceiptValidationErrorKind::HandoffMismatch => "handoff_mismatch",
            ShellHandoffReviewReceiptValidationErrorKind::ReviewedIdsMismatch => {
                "reviewed_ids_mismatch"
            }
            ShellHandoffReviewReceiptValidationErrorKind::StatusMismatch => "status_mismatch",
            ShellHandoffReviewReceiptValidationErrorKind::RuntimeStarted => "runtime_started",
        }
    }
}

impl fmt::Display for ShellHandoffReviewReceiptValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "shell handoff review {} rejected {}: {:?}",
            self.review_id, self.rejected_value, self.kind
        )
    }
}

impl std::error::Error for ShellHandoffReviewReceiptValidationError {}

/// Shell handoff review receipt validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellHandoffReviewReceiptValidationErrorKind {
    /// The receipt schema id is not supported.
    UnsupportedSchema,
    /// The receipt does not match the reviewed handoff identity.
    HandoffMismatch,
    /// The receipt reviewed ids drifted from the handoff.
    ReviewedIdsMismatch,
    /// Receipt status, checks, and issues disagree.
    StatusMismatch,
    /// The receipt indicates runtime, platform, launch, session, or legacy app work.
    RuntimeStarted,
}

/// Shell handoff validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellHandoffValidationError {
    handoff_id: DottedId,
    rejected_id: DottedId,
    kind: ShellHandoffValidationErrorKind,
}

impl ShellHandoffValidationError {
    fn new(
        handoff_id: DottedId,
        rejected_id: DottedId,
        kind: ShellHandoffValidationErrorKind,
    ) -> Self {
        Self {
            handoff_id,
            rejected_id,
            kind,
        }
    }

    /// Returns the affected shell handoff id.
    #[must_use]
    pub fn handoff_id(&self) -> &DottedId {
        &self.handoff_id
    }

    /// Returns the rejected stream, command, endpoint, or slot id.
    #[must_use]
    pub fn rejected_id(&self) -> &DottedId {
        &self.rejected_id
    }

    /// Returns the failure kind.
    #[must_use]
    pub const fn kind(&self) -> ShellHandoffValidationErrorKind {
        self.kind
    }

    /// Returns a stable rejection code.
    #[must_use]
    pub const fn rejection_code(&self) -> &'static str {
        match self.kind {
            ShellHandoffValidationErrorKind::UnknownStream => "unknown_stream",
            ShellHandoffValidationErrorKind::UnknownCommand => "unknown_command",
            ShellHandoffValidationErrorKind::UnknownEndpoint => "unknown_endpoint",
            ShellHandoffValidationErrorKind::UnknownValidationSlot => "unknown_validation_slot",
        }
    }
}

impl fmt::Display for ShellHandoffValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "shell handoff {} rejected {}: {:?}",
            self.handoff_id, self.rejected_id, self.kind
        )
    }
}

impl std::error::Error for ShellHandoffValidationError {}

/// Shell handoff validation failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellHandoffValidationErrorKind {
    /// The handoff references a stream absent from the selected registry.
    UnknownStream,
    /// The handoff references a command absent from the selected command set.
    UnknownCommand,
    /// The handoff references an endpoint absent from the selected host.
    UnknownEndpoint,
    /// The handoff references a validation slot absent from the selected bundle.
    UnknownValidationSlot,
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

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "serde"))]
mod serde_fixture_tests;
