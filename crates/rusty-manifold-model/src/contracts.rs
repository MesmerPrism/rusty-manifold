//! First-slice contract models for Manifold manifests and snapshots.

use core::fmt;

use crate::{DottedId, Revision, SchemaId};

mod bridge_route;
mod clock;
mod command_dispatch;
mod coordination;
mod expiry;
mod host_manifest;
mod ids;
mod leases;
mod media_session;
mod module_runtime;
mod samples;
mod streams;
mod validation_helpers;

pub use self::bridge_route::*;
pub use self::clock::*;
pub use self::command_dispatch::*;
pub use self::coordination::*;
pub use self::expiry::*;
pub use self::host_manifest::*;
use self::ids::*;
pub use self::leases::*;
pub use self::media_session::*;
pub use self::module_runtime::*;
pub use self::samples::*;
pub use self::streams::*;
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

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "serde"))]
mod serde_fixture_tests;
