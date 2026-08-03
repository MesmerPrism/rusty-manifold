//! Durable transport-neutral authority for a standalone connection hub.
//!
//! This crate owns trusted controller records, logical connection sessions,
//! monotonically advancing transport epochs, admitted provider registrations,
//! bounded UI-surface descriptors, derivative per-surface leases, command
//! authorization, explicit cleanup, replay protection, and restartable audit
//! lineage. It deliberately owns no socket, HTTP, WebSocket, Android, UI,
//! device API, high-rate payload, secret, or application effect.

use rusty_manifold_admission::{
    ManifoldAdmissionAuthority, ManifoldAdmissionOperation, ManifoldAdmissionSnapshot,
    ManifoldClientIdentity,
};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Authority policy schema.
pub const POLICY_SCHEMA: &str = "rusty.manifold.connection_hub.policy.v1";
/// Mutation request schema.
pub const REQUEST_SCHEMA: &str = "rusty.manifold.connection_hub.request.v1";
/// Accepted-state schema.
pub const STATE_SCHEMA: &str = "rusty.manifold.connection_hub.state.v1";
/// Restart snapshot schema.
pub const SNAPSHOT_SCHEMA: &str = "rusty.manifold.connection_hub.snapshot.v1";
/// Mutation receipt schema.
pub const RECEIPT_SCHEMA: &str = "rusty.manifold.connection_hub.receipt.v1";
/// Audit-event schema.
pub const AUDIT_SCHEMA: &str = "rusty.manifold.connection_hub.audit_event.v1";
/// Surface descriptor schema.
pub const SURFACE_SCHEMA: &str = "rusty.manifold.connection_hub.surface.v1";
/// Provider-admission record schema.
pub const PROVIDER_SCHEMA: &str = "rusty.manifold.connection_hub.provider.v1";
/// Logical session schema.
pub const SESSION_SCHEMA: &str = "rusty.manifold.connection_hub.session.v1";
/// Derivative surface-lease schema.
pub const SURFACE_LEASE_SCHEMA: &str = "rusty.manifold.connection_hub.surface_lease.v1";
/// Surface command-authorization schema.
pub const COMMAND_AUTHORIZATION_SCHEMA: &str =
    "rusty.manifold.connection_hub.command_authorization.v1";

/// Admission capability consumed when a provider instance joins the Hub.
pub const PROVIDER_REGISTER_CAPABILITY: &str = "capability.connection_hub.provider.register";

const MAX_CONTROLLERS: usize = 32;
const MAX_SESSIONS: usize = 32;
const MAX_PROVIDERS: usize = 64;
const MAX_SURFACES: usize = 128;
const MAX_SURFACE_LEASES: usize = 256;
const MAX_COMMANDS_PER_SURFACE: usize = 64;
const MAX_CAPABILITIES: usize = 64;
const MAX_REPLAY_RECORDS: usize = 4096;
const MAX_AUDIT_EVENTS: usize = 4096;
// Command and ordinary lifecycle traffic cannot consume the final retained
// slots. Those slots remain available for terminal cleanup operations.
const MAX_ORDINARY_AUDIT_EVENTS: usize = 3840;
const MAX_TOMBSTONES: usize = 4096;
const MAX_CONTROLLER_TTL_MS: u64 = 366 * 24 * 60 * 60 * 1_000;
const MAX_SESSION_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_SURFACE_LEASE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_SNAPSHOT_JSON_BYTES: usize = 8 * 1024 * 1024;

/// One closed provider grant in Hub product policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubProviderGrant {
    /// Exact provider family identity this grant may register.
    pub provider_id: DottedId,
    /// Stable admitted Manifold client identity.
    pub client_id: DottedId,
    /// Exact packaged client-lock identity.
    pub client_lock_id: DottedId,
    /// Exact packaged client-lock SHA-256.
    pub client_lock_sha256: String,
    /// SHA-256 of the exact separately packaged surface contract.
    pub surface_contract_sha256: String,
    /// Exact sorted command-to-controller-capability registry this provider
    /// may expose. Capability requirements cannot be lowered at runtime.
    pub allowed_commands: Vec<ManifoldConnectionHubSurfaceCommand>,
}

/// Immutable authority policy supplied by the standalone product lock owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubPolicy {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable Hub authority identity.
    pub authority_id: DottedId,
    /// Exact operator evidence identities accepted for trust decisions.
    pub trusted_operator_evidence_ids: Vec<DottedId>,
    /// Exact capabilities that may be assigned to a controller.
    pub allowed_controller_capabilities: Vec<DottedId>,
    /// Exact admitted provider grants.
    pub provider_grants: Vec<ManifoldConnectionHubProviderGrant>,
    /// Maximum durable controller trust lifetime.
    pub max_controller_ttl_ms: u64,
    /// Maximum logical connection-session lifetime.
    pub max_session_ttl_ms: u64,
    /// Maximum derivative surface-lease lifetime.
    pub max_surface_lease_ttl_ms: u64,
}

/// Durable trusted controller identity. The SHA-256 binds a public identity;
/// no bearer or pairing secret is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubTrustedController {
    /// Stable logical controller identity.
    pub controller_id: DottedId,
    /// SHA-256 of the controller's public identity material.
    pub public_identity_sha256: String,
    /// Exact sorted controller capabilities.
    pub capabilities: Vec<DottedId>,
    /// Operator evidence that admitted this trust record.
    pub operator_evidence_id: DottedId,
    /// Trust creation time.
    pub trusted_at_ms: u64,
    /// Absolute trust expiry.
    pub expires_at_ms: u64,
}

/// Adapter-owned transport evidence bound to a logical session epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubTransportBinding {
    /// Opaque transport instance identity; never an endpoint or token.
    pub transport_id: DottedId,
    /// Low-sensitivity downstream evidence identity.
    pub evidence_id: DottedId,
    /// Time the adapter attached this transport.
    pub attached_at_ms: u64,
}

/// Logical connection session independent of any one socket instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubSession {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable logical session identity.
    pub session_id: DottedId,
    /// Durable trusted controller identity.
    pub controller_id: DottedId,
    /// Session creation time.
    pub opened_at_ms: u64,
    /// Absolute session expiry.
    pub expires_at_ms: u64,
    /// Monotonic transport generation. It starts at one and never regresses.
    pub transport_epoch: u64,
    /// Current adapter transport evidence.
    pub transport: ManifoldConnectionHubTransportBinding,
}

/// Provider registration tied to a separately accepted admission use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubProvider {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable provider family identity.
    pub provider_id: DottedId,
    /// Fresh provider-process instance identity.
    pub provider_instance_id: DottedId,
    /// Platform-projected client identity.
    pub identity: ManifoldClientIdentity,
    /// Exact packaged client-lock identity.
    pub client_lock_id: DottedId,
    /// Exact packaged client-lock SHA-256.
    pub client_lock_sha256: String,
    /// Admission authority that accepted the provider use.
    pub admission_authority_id: DottedId,
    /// Admission revision containing the accepted use.
    pub admission_authority_revision: Revision,
    /// One-time accepted provider-registration use identity.
    pub admission_use_request_id: DottedId,
    /// Expiry inherited from the admitted token.
    pub admission_expires_at_ms: u64,
    /// Exact surface-contract digest retained from product policy.
    pub surface_contract_sha256: String,
    /// Exact command-to-capability registry retained from product policy.
    pub allowed_commands: Vec<ManifoldConnectionHubSurfaceCommand>,
    /// Registration time.
    pub registered_at_ms: u64,
}

/// One command exposed by an app-owned UI surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubSurfaceCommand {
    /// Closed Manifold command identity.
    pub command_id: DottedId,
    /// Capability the durable controller must hold.
    pub required_controller_capability: DottedId,
}

/// Low-rate UI-surface registration. It describes a control surface but
/// carries no HTML, script, URL, component, route, media, or effect payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubSurface {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable surface identity.
    pub surface_id: DottedId,
    /// Owning provider family.
    pub provider_id: DottedId,
    /// Exact live provider instance.
    pub provider_instance_id: DottedId,
    /// Display-safe label.
    pub display_label: String,
    /// Display-safe description.
    pub description: String,
    /// SHA-256 of the separately packaged surface contract bytes.
    pub surface_contract_sha256: String,
    /// Exact sorted closed command registry.
    pub commands: Vec<ManifoldConnectionHubSurfaceCommand>,
    /// Registration time.
    pub registered_at_ms: u64,
}

/// Derivative lease selecting one surface for one logical session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubSurfaceLease {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable derivative lease identity.
    pub lease_id: DottedId,
    /// Parent logical session.
    pub session_id: DottedId,
    /// Parent controller.
    pub controller_id: DottedId,
    /// Selected surface.
    pub surface_id: DottedId,
    /// Exact owning provider instance.
    pub provider_instance_id: DottedId,
    /// Transport epoch observed at issue. Replacement does not revoke this
    /// logical lease, but command use must present the current epoch.
    pub issued_transport_epoch: u64,
    /// Issue time.
    pub issued_at_ms: u64,
    /// Absolute expiry.
    pub expires_at_ms: u64,
}

/// Successfully authorized low-rate surface command. This never proves an app
/// effect and carries no arbitrary parameter payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubCommandAuthorization {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-time authorization identity.
    pub authorization_id: DottedId,
    /// Source request identity.
    pub request_id: DottedId,
    /// Logical session.
    pub session_id: DottedId,
    /// Current transport epoch.
    pub transport_epoch: u64,
    /// Derivative surface lease.
    pub lease_id: DottedId,
    /// Surface identity.
    pub surface_id: DottedId,
    /// Exact live provider instance.
    pub provider_instance_id: DottedId,
    /// Exact provider family authorized by product policy.
    pub provider_id: DottedId,
    /// Exact registered and product-authorized surface-contract digest.
    pub surface_contract_sha256: String,
    /// Closed command identity.
    pub command_id: DottedId,
    /// Exact controller capability required by product policy.
    pub required_controller_capability: DottedId,
    /// SHA-256 of the exact canonical low-rate typed command parameters. The
    /// parameter bytes themselves remain downstream and are never retained by
    /// Manifold.
    pub typed_params_sha256: String,
    /// Command admission is not application effect evidence.
    pub proves_application_effect: bool,
}

/// Retired identity retained against resurrection and for cleanup audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubTombstone {
    /// Retired object class.
    pub subject_kind: ManifoldConnectionHubSubjectKind,
    /// Retired stable identity.
    pub subject_id: DottedId,
    /// Cleanup reason.
    pub reason: DottedId,
    /// Cleanup request.
    pub request_id: DottedId,
    /// Cleanup time.
    pub retired_at_ms: u64,
}

/// Retired object class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldConnectionHubSubjectKind {
    /// Durable controller trust.
    Controller,
    /// Logical session.
    Session,
    /// Admitted provider instance.
    Provider,
    /// Registered UI surface.
    Surface,
    /// Derivative surface lease.
    SurfaceLease,
}

/// Complete accepted low-rate Hub state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubState {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable authority identity.
    pub authority_id: DottedId,
    /// Current accepted revision.
    pub authority_revision: Revision,
    /// Durable trusted controllers.
    pub trusted_controllers: Vec<ManifoldConnectionHubTrustedController>,
    /// Active logical connection sessions.
    pub sessions: Vec<ManifoldConnectionHubSession>,
    /// Active admitted provider instances.
    pub providers: Vec<ManifoldConnectionHubProvider>,
    /// Active registered app-owned surfaces.
    pub surfaces: Vec<ManifoldConnectionHubSurface>,
    /// Active derivative surface leases.
    pub surface_leases: Vec<ManifoldConnectionHubSurfaceLease>,
    /// Terminal cleanup lineage.
    pub tombstones: Vec<ManifoldConnectionHubTombstone>,
}

/// One complete operation-specific request body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "type",
    content = "details",
    rename_all = "snake_case"
)]
pub enum ManifoldConnectionHubOperationRequest {
    /// Admit a durable trusted controller after adapter-owned verification.
    TrustController {
        /// Controller identity.
        controller_id: DottedId,
        /// Public controller identity SHA-256.
        public_identity_sha256: String,
        /// Exact sorted capability subset.
        capabilities: Vec<DottedId>,
        /// Trusted operator evidence.
        operator_evidence_id: DottedId,
        /// Requested trust lifetime.
        requested_ttl_ms: u64,
    },
    /// Explicitly forget one durable controller and all descendants.
    ForgetController {
        /// Controller identity.
        controller_id: DottedId,
        /// Operator evidence authorizing removal.
        operator_evidence_id: DottedId,
        /// Low-sensitivity reason.
        reason: DottedId,
    },
    /// Open a logical session with initial transport epoch one.
    OpenSession {
        /// New logical session identity.
        session_id: DottedId,
        /// Trusted controller.
        controller_id: DottedId,
        /// Public identity SHA-256 presented by the adapter.
        public_identity_sha256: String,
        /// Initial transport evidence.
        transport: ManifoldConnectionHubTransportBinding,
        /// Requested lifetime.
        requested_ttl_ms: u64,
    },
    /// Replace only the physical transport of an existing logical session.
    ReplaceTransport {
        /// Logical session identity.
        session_id: DottedId,
        /// Exact current epoch required by the caller.
        expected_transport_epoch: u64,
        /// Fresh replacement transport evidence.
        transport: ManifoldConnectionHubTransportBinding,
    },
    /// Register one separately admitted app provider instance.
    RegisterProvider {
        /// Provider family identity.
        provider_id: DottedId,
        /// Fresh process instance identity.
        provider_instance_id: DottedId,
        /// One-time accepted admission capability-use request.
        admission_use_request_id: DottedId,
    },
    /// Remove one exact provider instance and all surfaces/leases derived from it.
    UnregisterProvider {
        /// Provider family identity.
        provider_id: DottedId,
        /// Exact live process instance.
        provider_instance_id: DottedId,
        /// `provider_unregistered` or `provider_died` style reason.
        reason: DottedId,
    },
    /// Register one bounded app-owned UI surface.
    RegisterSurface {
        /// Surface descriptor.
        surface: ManifoldConnectionHubSurface,
    },
    /// Remove one surface and its derivative leases.
    UnregisterSurface {
        /// Surface identity.
        surface_id: DottedId,
        /// Exact provider instance.
        provider_instance_id: DottedId,
        /// Low-sensitivity reason.
        reason: DottedId,
    },
    /// Acquire a derivative lease for one session and surface.
    AcquireSurfaceLease {
        /// New lease identity.
        lease_id: DottedId,
        /// Logical session.
        session_id: DottedId,
        /// Current transport epoch.
        expected_transport_epoch: u64,
        /// Surface identity.
        surface_id: DottedId,
        /// Requested lifetime.
        requested_ttl_ms: u64,
    },
    /// Release one derivative surface lease.
    ReleaseSurfaceLease {
        /// Lease identity.
        lease_id: DottedId,
        /// Parent session.
        session_id: DottedId,
        /// Low-sensitivity reason.
        reason: DottedId,
    },
    /// Authorize one closed command against the current session epoch and lease.
    AuthorizeSurfaceCommand {
        /// Logical session.
        session_id: DottedId,
        /// Current transport epoch.
        expected_transport_epoch: u64,
        /// Derivative surface lease.
        lease_id: DottedId,
        /// Closed command identity.
        command_id: DottedId,
        /// SHA-256 of the exact canonical low-rate typed parameters.
        typed_params_sha256: String,
    },
    /// Explicitly revoke one logical session and its derivative leases.
    RevokeSession {
        /// Logical session.
        session_id: DottedId,
        /// Low-sensitivity reason.
        reason: DottedId,
    },
    /// Explicit trusted-clock cleanup of expired controllers, sessions,
    /// provider admissions, and surface leases.
    Expire,
}

/// One revision-guarded Hub mutation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-time request identity.
    pub request_id: DottedId,
    /// Exact current authority revision.
    pub expected_authority_revision: Revision,
    /// Trusted authority observation time.
    pub requested_at_ms: u64,
    /// Operation-specific body.
    pub operation: ManifoldConnectionHubOperationRequest,
}

/// Stable operation label in receipts and audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldConnectionHubOperation {
    /// Durable trust creation.
    TrustController,
    /// Durable trust removal.
    ForgetController,
    /// Logical session creation.
    OpenSession,
    /// Physical transport replacement.
    ReplaceTransport,
    /// Provider admission.
    RegisterProvider,
    /// Provider removal/death cleanup.
    UnregisterProvider,
    /// Surface registration.
    RegisterSurface,
    /// Surface removal.
    UnregisterSurface,
    /// Derivative lease issue.
    AcquireSurfaceLease,
    /// Derivative lease release.
    ReleaseSurfaceLease,
    /// One command authorization.
    AuthorizeSurfaceCommand,
    /// Logical session revocation.
    RevokeSession,
    /// Explicit expiry cleanup.
    Expire,
}

/// Machine-readable fail-closed rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldConnectionHubRejectionReason {
    /// Contract schema differs.
    SchemaMismatch,
    /// Platform time, verified operator evidence, or retained admission
    /// evidence did not match the operation's non-serializable owner context.
    OwnerContextMismatch,
    /// Request expected a different accepted revision.
    StaleAuthorityRevision,
    /// Request identity or exact request digest was already applied.
    Replay,
    /// Retained capacity is exhausted.
    CapacityExceeded,
    /// Authority revision cannot advance.
    RevisionExhausted,
    /// Operator evidence is outside policy.
    OperatorNotTrusted,
    /// Controller is unknown, retired, expired, or identity-substituted.
    ControllerNotTrusted,
    /// Controller capability request exceeds policy or command requirements.
    ControllerCapabilityDenied,
    /// TTL is zero, too long, or exceeds a parent lifetime.
    InvalidLifetime,
    /// A live or retired identity would be reused.
    IdentityCollision,
    /// Logical session is absent, expired, or controller-substituted.
    SessionNotActive,
    /// Transport epoch is stale or not monotonic.
    TransportEpochMismatch,
    /// Replacement transport evidence aliases the current transport.
    TransportSubstitution,
    /// Separate admission state does not prove the exact provider registration.
    ProviderAdmissionRejected,
    /// Provider is absent, expired, or instance-substituted.
    ProviderNotActive,
    /// Surface descriptor is malformed or exceeds its provider grant.
    SurfaceNotAllowed,
    /// Surface is absent or provider-substituted.
    SurfaceNotActive,
    /// Derivative surface lease is absent, expired, or parent-substituted.
    SurfaceLeaseNotActive,
    /// Command is not in the exact registered surface command set.
    CommandNotRegistered,
    /// Canonical typed-parameter digest is malformed.
    InvalidTypedParamsDigest,
    /// Explicit expiry found no expired accepted state.
    NothingExpired,
}

/// One accepted mutation audit event. Request and digest are retained so
/// replay and substitution remain inspectable after restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubAuditEvent {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Strictly increasing event sequence.
    pub sequence: u64,
    /// Deterministic event identity.
    pub event_id: DottedId,
    /// Operation.
    pub operation: ManifoldConnectionHubOperation,
    /// Complete accepted request.
    pub request: ManifoldConnectionHubRequest,
    /// SHA-256 of exact typed request JSON.
    pub request_sha256: String,
    /// Prior accepted revision.
    pub prior_authority_revision: Revision,
    /// Resulting accepted revision.
    pub resulting_authority_revision: Revision,
    /// SHA-256 of exact resulting state JSON.
    pub resulting_state_sha256: String,
}

/// Durable restart snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubSnapshot {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Immutable policy.
    pub policy: ManifoldConnectionHubPolicy,
    /// Current accepted state.
    pub state: ManifoldConnectionHubState,
    /// Accepted request identities, in application order.
    pub applied_request_ids: Vec<DottedId>,
    /// Exact accepted request digests, in application order.
    pub applied_request_sha256: Vec<String>,
    /// Append-only accepted audit lineage.
    pub audit_events: Vec<ManifoldConnectionHubAuditEvent>,
}

/// Applied or rejected mutation receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Stable receipt identity.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// Operation.
    pub operation: ManifoldConnectionHubOperation,
    /// Whether accepted state advanced.
    pub applied: bool,
    /// Prior revision.
    pub prior_authority_revision: Revision,
    /// Resulting revision.
    pub resulting_authority_revision: Revision,
    /// Rejection when state did not advance.
    pub rejection_reason: Option<ManifoldConnectionHubRejectionReason>,
    /// Resulting or selected session where applicable.
    pub session: Option<ManifoldConnectionHubSession>,
    /// Resulting surface lease where applicable.
    pub surface_lease: Option<ManifoldConnectionHubSurfaceLease>,
    /// Resulting one-time command authorization where applicable.
    pub command_authorization: Option<ManifoldConnectionHubCommandAuthorization>,
    /// Sorted identities removed as derivative cleanup.
    pub cleaned_subject_ids: Vec<DottedId>,
    /// Accepted audit event.
    pub audit_event: Option<ManifoldConnectionHubAuditEvent>,
}

/// Non-serializable owner evidence required to apply a request. This context
/// must be constructed inside the retained Hub owner from platform time,
/// verified wearer/operator evidence, or its in-process admission authority;
/// it is deliberately not accepted from protocol JSON.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldConnectionHubOwnerContext<'a> {
    observed_at_ms: u64,
    verified_operator_evidence_id: Option<&'a DottedId>,
    admission_snapshot: Option<&'a ManifoldAdmissionSnapshot>,
}

impl<'a> ManifoldConnectionHubOwnerContext<'a> {
    /// Context for lifecycle operations that require only platform time.
    #[must_use]
    pub const fn lifecycle(observed_at_ms: u64) -> Self {
        Self {
            observed_at_ms,
            verified_operator_evidence_id: None,
            admission_snapshot: None,
        }
    }

    /// Context for a fixed owner-verified operator decision.
    #[must_use]
    pub const fn operator_decision(
        observed_at_ms: u64,
        verified_operator_evidence_id: &'a DottedId,
    ) -> Self {
        Self {
            observed_at_ms,
            verified_operator_evidence_id: Some(verified_operator_evidence_id),
            admission_snapshot: None,
        }
    }

    /// Context for provider registration from the retained admission owner.
    #[must_use]
    pub const fn provider_admission(
        observed_at_ms: u64,
        admission_snapshot: &'a ManifoldAdmissionSnapshot,
    ) -> Self {
        Self {
            observed_at_ms,
            verified_operator_evidence_id: None,
            admission_snapshot: Some(admission_snapshot),
        }
    }
}

/// Authority construction, restart, or snapshot validation failure.
#[derive(Debug)]
pub enum ManifoldConnectionHubError {
    /// JSON encoding/decoding failed.
    Json(serde_json::Error),
    /// Snapshot exceeds the input bound.
    SnapshotTooLarge,
    /// Policy is malformed.
    InvalidPolicy(&'static str),
    /// Snapshot lineage or accepted state is malformed.
    InvalidSnapshot(&'static str),
}

impl fmt::Display for ManifoldConnectionHubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "{error}"),
            Self::SnapshotTooLarge => formatter.write_str("connection hub snapshot is too large"),
            Self::InvalidPolicy(reason) => write!(formatter, "invalid policy: {reason}"),
            Self::InvalidSnapshot(reason) => write!(formatter, "invalid snapshot: {reason}"),
        }
    }
}

impl std::error::Error for ManifoldConnectionHubError {}

impl From<serde_json::Error> for ManifoldConnectionHubError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Restartable source-only Connection Hub authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldConnectionHubAuthority {
    snapshot: ManifoldConnectionHubSnapshot,
}

impl ManifoldConnectionHubAuthority {
    /// Creates empty accepted state from one exact product policy.
    ///
    /// # Errors
    ///
    /// Rejects malformed ordering, duplicate identities, unsafe lifetimes, or
    /// malformed digest fields in policy.
    pub fn new(policy: ManifoldConnectionHubPolicy) -> Result<Self, ManifoldConnectionHubError> {
        validate_policy(&policy)?;
        let authority_id = policy.authority_id.clone();
        Ok(Self {
            snapshot: ManifoldConnectionHubSnapshot {
                schema_id: schema(SNAPSHOT_SCHEMA),
                policy,
                state: ManifoldConnectionHubState {
                    schema_id: schema(STATE_SCHEMA),
                    authority_id,
                    authority_revision: Revision::INITIAL,
                    trusted_controllers: Vec::new(),
                    sessions: Vec::new(),
                    providers: Vec::new(),
                    surfaces: Vec::new(),
                    surface_leases: Vec::new(),
                    tombstones: Vec::new(),
                },
                applied_request_ids: Vec::new(),
                applied_request_sha256: Vec::new(),
                audit_events: Vec::new(),
            },
        })
    }

    /// Returns the complete accepted snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ManifoldConnectionHubSnapshot {
        &self.snapshot
    }

    /// Returns deterministic pretty JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns JSON serialization errors.
    pub fn snapshot_json(&self) -> Result<String, serde_json::Error> {
        let mut value = serde_json::to_string_pretty(&self.snapshot)?;
        value.push('\n');
        Ok(value)
    }

    /// Restarts from exact validated JSON.
    ///
    /// # Errors
    ///
    /// Rejects oversized, unknown-field, malformed, noncanonical, replay-
    /// damaged, digest-substituted, or lineage-damaged snapshots.
    pub fn restart_from_json(value: &str) -> Result<Self, ManifoldConnectionHubError> {
        if value.len() > MAX_SNAPSHOT_JSON_BYTES {
            return Err(ManifoldConnectionHubError::SnapshotTooLarge);
        }
        let snapshot: ManifoldConnectionHubSnapshot = serde_json::from_str(value)?;
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot })
    }

    /// Applies one request with non-serializable evidence from the retained
    /// owner. Provider registration additionally requires that owner's exact
    /// current admission snapshot.
    #[must_use]
    pub fn apply(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        let operation = operation_label(&request.operation);
        let prior = self.snapshot.state.authority_revision;
        let request_digest = typed_sha256(request);
        let generic_rejection = if request.schema_id.as_str() != REQUEST_SCHEMA {
            Some(ManifoldConnectionHubRejectionReason::SchemaMismatch)
        } else if !owner_context_matches(request, owner_context) {
            Some(ManifoldConnectionHubRejectionReason::OwnerContextMismatch)
        } else if self
            .snapshot
            .applied_request_ids
            .iter()
            .any(|id| id == &request.request_id)
            || self
                .snapshot
                .applied_request_sha256
                .iter()
                .any(|digest| digest == &request_digest)
            || provider_admission_use_replayed(&self.snapshot.audit_events, &request.operation)
        {
            Some(ManifoldConnectionHubRejectionReason::Replay)
        } else if request.expected_authority_revision != prior {
            Some(ManifoldConnectionHubRejectionReason::StaleAuthorityRevision)
        } else if self.snapshot.applied_request_ids.len() >= MAX_REPLAY_RECORDS
            || self.snapshot.audit_events.len() >= MAX_AUDIT_EVENTS
            || (!is_terminal_cleanup_operation(&request.operation)
                && self.snapshot.audit_events.len() >= MAX_ORDINARY_AUDIT_EVENTS)
        {
            Some(ManifoldConnectionHubRejectionReason::CapacityExceeded)
        } else {
            None
        };
        if let Some(reason) = generic_rejection {
            return rejected_receipt(request, operation, prior, reason);
        }
        let Some(resulting_revision) = prior.next() else {
            return rejected_receipt(
                request,
                operation,
                prior,
                ManifoldConnectionHubRejectionReason::RevisionExhausted,
            );
        };

        let mut state = self.snapshot.state.clone();
        let outcome = apply_operation(
            &self.snapshot.policy,
            &mut state,
            request,
            owner_context.admission_snapshot,
            resulting_revision,
        );
        let output = match outcome {
            Ok(output) => output,
            Err(reason) => return rejected_receipt(request, operation, prior, reason),
        };
        state.authority_revision = resulting_revision;
        canonicalize_state(&mut state);
        if validate_state(&self.snapshot.policy, &state).is_err() {
            return rejected_receipt(
                request,
                operation,
                prior,
                ManifoldConnectionHubRejectionReason::CapacityExceeded,
            );
        }
        let state_digest = typed_sha256(&state);
        let sequence = self.snapshot.audit_events.len() as u64 + 1;
        let event_id = artifact_id("audit.connection-hub", &request.request_id, sequence);
        let audit_event = ManifoldConnectionHubAuditEvent {
            schema_id: schema(AUDIT_SCHEMA),
            sequence,
            event_id,
            operation: operation.clone(),
            request: request.clone(),
            request_sha256: request_digest.clone(),
            prior_authority_revision: prior,
            resulting_authority_revision: resulting_revision,
            resulting_state_sha256: state_digest,
        };
        self.snapshot.state = state;
        self.snapshot
            .applied_request_ids
            .push(request.request_id.clone());
        self.snapshot.applied_request_sha256.push(request_digest);
        self.snapshot.audit_events.push(audit_event.clone());

        ManifoldConnectionHubReceipt {
            schema_id: schema(RECEIPT_SCHEMA),
            receipt_id: artifact_id("receipt.connection-hub", &request.request_id, sequence),
            request_id: request.request_id.clone(),
            operation,
            applied: true,
            prior_authority_revision: prior,
            resulting_authority_revision: resulting_revision,
            rejection_reason: None,
            session: output.session,
            surface_lease: output.surface_lease,
            command_authorization: output.command_authorization,
            cleaned_subject_ids: output.cleaned_subject_ids,
            audit_event: Some(audit_event),
        }
    }

    /// Applies a controller trust request.
    #[must_use]
    pub fn trust_controller(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.apply(request, owner_context)
    }

    /// Applies a durable controller removal request.
    #[must_use]
    pub fn forget_controller(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.apply(request, owner_context)
    }

    /// Applies a logical-session open request.
    #[must_use]
    pub fn open_session(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.apply(request, owner_context)
    }

    /// Applies a physical transport replacement request.
    #[must_use]
    pub fn replace_transport(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.apply(request, owner_context)
    }

    /// Registers a provider from exact current admission evidence.
    #[must_use]
    pub fn register_provider(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.apply(request, owner_context)
    }

    /// Applies any non-provider-registration lifecycle request.
    #[must_use]
    pub fn apply_lifecycle(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_context: ManifoldConnectionHubOwnerContext<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.apply(request, owner_context)
    }
}

#[derive(Default)]
struct ApplyOutput {
    session: Option<ManifoldConnectionHubSession>,
    surface_lease: Option<ManifoldConnectionHubSurfaceLease>,
    command_authorization: Option<ManifoldConnectionHubCommandAuthorization>,
    cleaned_subject_ids: Vec<DottedId>,
}

#[allow(clippy::too_many_lines)]
fn apply_operation(
    policy: &ManifoldConnectionHubPolicy,
    state: &mut ManifoldConnectionHubState,
    request: &ManifoldConnectionHubRequest,
    admission: Option<&ManifoldAdmissionSnapshot>,
    resulting_revision: Revision,
) -> Result<ApplyOutput, ManifoldConnectionHubRejectionReason> {
    match &request.operation {
        ManifoldConnectionHubOperationRequest::TrustController {
            controller_id,
            public_identity_sha256,
            capabilities,
            operator_evidence_id,
            requested_ttl_ms,
        } => {
            require_operator(policy, operator_evidence_id)?;
            if !is_sha256(public_identity_sha256)
                || !is_sorted_unique(capabilities)
                || capabilities.is_empty()
                || capabilities.len() > MAX_CAPABILITIES
                || !capabilities
                    .iter()
                    .all(|capability| policy.allowed_controller_capabilities.contains(capability))
            {
                return Err(ManifoldConnectionHubRejectionReason::ControllerCapabilityDenied);
            }
            let expires_at_ms = checked_expiry(
                request.requested_at_ms,
                *requested_ttl_ms,
                policy.max_controller_ttl_ms,
                None,
            )?;
            if state
                .trusted_controllers
                .iter()
                .any(|controller| &controller.controller_id == controller_id)
                || is_retired(
                    state,
                    ManifoldConnectionHubSubjectKind::Controller,
                    controller_id,
                )
            {
                return Err(ManifoldConnectionHubRejectionReason::IdentityCollision);
            }
            if state.trusted_controllers.len() >= MAX_CONTROLLERS {
                return Err(ManifoldConnectionHubRejectionReason::CapacityExceeded);
            }
            state
                .trusted_controllers
                .push(ManifoldConnectionHubTrustedController {
                    controller_id: controller_id.clone(),
                    public_identity_sha256: public_identity_sha256.clone(),
                    capabilities: capabilities.clone(),
                    operator_evidence_id: operator_evidence_id.clone(),
                    trusted_at_ms: request.requested_at_ms,
                    expires_at_ms,
                });
            Ok(ApplyOutput::default())
        }
        ManifoldConnectionHubOperationRequest::ForgetController {
            controller_id,
            operator_evidence_id,
            reason,
        } => {
            require_operator(policy, operator_evidence_id)?;
            let position = state
                .trusted_controllers
                .iter()
                .position(|controller| &controller.controller_id == controller_id)
                .ok_or(ManifoldConnectionHubRejectionReason::ControllerNotTrusted)?;
            state.trusted_controllers.remove(position);
            let mut output = ApplyOutput::default();
            cleanup_controller(state, controller_id, request, reason, &mut output)?;
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::Controller,
                controller_id.clone(),
                reason.clone(),
                request,
            )?;
            output.cleaned_subject_ids.push(controller_id.clone());
            sort_dedupe_ids(&mut output.cleaned_subject_ids);
            Ok(output)
        }
        ManifoldConnectionHubOperationRequest::OpenSession {
            session_id,
            controller_id,
            public_identity_sha256,
            transport,
            requested_ttl_ms,
        } => {
            let controller = state
                .trusted_controllers
                .iter()
                .find(|controller| &controller.controller_id == controller_id)
                .ok_or(ManifoldConnectionHubRejectionReason::ControllerNotTrusted)?;
            if controller.expires_at_ms <= request.requested_at_ms
                || &controller.public_identity_sha256 != public_identity_sha256
            {
                return Err(ManifoldConnectionHubRejectionReason::ControllerNotTrusted);
            }
            validate_transport(transport, request.requested_at_ms)?;
            let expires_at_ms = checked_expiry(
                request.requested_at_ms,
                *requested_ttl_ms,
                policy.max_session_ttl_ms,
                Some(controller.expires_at_ms),
            )?;
            if state
                .sessions
                .iter()
                .any(|session| &session.session_id == session_id)
                || is_retired(state, ManifoldConnectionHubSubjectKind::Session, session_id)
            {
                return Err(ManifoldConnectionHubRejectionReason::IdentityCollision);
            }
            if state.sessions.len() >= MAX_SESSIONS {
                return Err(ManifoldConnectionHubRejectionReason::CapacityExceeded);
            }
            let session = ManifoldConnectionHubSession {
                schema_id: schema(SESSION_SCHEMA),
                session_id: session_id.clone(),
                controller_id: controller_id.clone(),
                opened_at_ms: request.requested_at_ms,
                expires_at_ms,
                transport_epoch: 1,
                transport: transport.clone(),
            };
            state.sessions.push(session.clone());
            Ok(ApplyOutput {
                session: Some(session),
                ..ApplyOutput::default()
            })
        }
        ManifoldConnectionHubOperationRequest::ReplaceTransport {
            session_id,
            expected_transport_epoch,
            transport,
        } => {
            validate_transport(transport, request.requested_at_ms)?;
            let session = state
                .sessions
                .iter_mut()
                .find(|session| &session.session_id == session_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SessionNotActive)?;
            if session.expires_at_ms <= request.requested_at_ms {
                return Err(ManifoldConnectionHubRejectionReason::SessionNotActive);
            }
            if session.transport_epoch != *expected_transport_epoch {
                return Err(ManifoldConnectionHubRejectionReason::TransportEpochMismatch);
            }
            if session.transport.transport_id == transport.transport_id
                || session.transport.evidence_id == transport.evidence_id
                || transport.attached_at_ms < session.transport.attached_at_ms
            {
                return Err(ManifoldConnectionHubRejectionReason::TransportSubstitution);
            }
            session.transport_epoch = session
                .transport_epoch
                .checked_add(1)
                .ok_or(ManifoldConnectionHubRejectionReason::TransportEpochMismatch)?;
            session.transport = transport.clone();
            Ok(ApplyOutput {
                session: Some(session.clone()),
                ..ApplyOutput::default()
            })
        }
        ManifoldConnectionHubOperationRequest::RegisterProvider {
            provider_id,
            provider_instance_id,
            admission_use_request_id,
        } => {
            let admission =
                admission.ok_or(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)?;
            let provider = validate_provider_admission(
                policy,
                admission,
                provider_id,
                provider_instance_id,
                admission_use_request_id,
                request.requested_at_ms,
            )?;
            if state.providers.iter().any(|existing| {
                existing.provider_id == *provider_id
                    || existing.provider_instance_id == *provider_instance_id
            }) || is_retired(
                state,
                ManifoldConnectionHubSubjectKind::Provider,
                provider_instance_id,
            ) {
                return Err(ManifoldConnectionHubRejectionReason::IdentityCollision);
            }
            if state.providers.len() >= MAX_PROVIDERS {
                return Err(ManifoldConnectionHubRejectionReason::CapacityExceeded);
            }
            state.providers.push(provider);
            Ok(ApplyOutput::default())
        }
        ManifoldConnectionHubOperationRequest::UnregisterProvider {
            provider_id,
            provider_instance_id,
            reason,
        } => {
            let position = state
                .providers
                .iter()
                .position(|provider| {
                    &provider.provider_id == provider_id
                        && &provider.provider_instance_id == provider_instance_id
                })
                .ok_or(ManifoldConnectionHubRejectionReason::ProviderNotActive)?;
            state.providers.remove(position);
            let mut output = ApplyOutput::default();
            cleanup_provider(state, provider_instance_id, request, reason, &mut output)?;
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::Provider,
                provider_instance_id.clone(),
                reason.clone(),
                request,
            )?;
            output
                .cleaned_subject_ids
                .push(provider_instance_id.clone());
            sort_dedupe_ids(&mut output.cleaned_subject_ids);
            Ok(output)
        }
        ManifoldConnectionHubOperationRequest::RegisterSurface { surface } => {
            if surface.schema_id.as_str() != SURFACE_SCHEMA
                || surface.registered_at_ms != request.requested_at_ms
                || surface.display_label.is_empty()
                || surface.display_label.chars().count() > 96
                || surface.description.chars().count() > 160
                || !is_sha256(&surface.surface_contract_sha256)
                || surface.commands.is_empty()
                || surface.commands.len() > MAX_COMMANDS_PER_SURFACE
                || !is_sorted_unique_by(&surface.commands, |command| &command.command_id)
            {
                return Err(ManifoldConnectionHubRejectionReason::SurfaceNotAllowed);
            }
            let provider = state
                .providers
                .iter()
                .find(|provider| {
                    provider.provider_id == surface.provider_id
                        && provider.provider_instance_id == surface.provider_instance_id
                })
                .ok_or(ManifoldConnectionHubRejectionReason::ProviderNotActive)?;
            if provider.admission_expires_at_ms <= request.requested_at_ms {
                return Err(ManifoldConnectionHubRejectionReason::ProviderNotActive);
            }
            if surface.surface_contract_sha256 != provider.surface_contract_sha256
                || surface.commands != provider.allowed_commands
            {
                return Err(ManifoldConnectionHubRejectionReason::SurfaceNotAllowed);
            }
            if state
                .surfaces
                .iter()
                .any(|existing| existing.surface_id == surface.surface_id)
                || is_retired(
                    state,
                    ManifoldConnectionHubSubjectKind::Surface,
                    &surface.surface_id,
                )
            {
                return Err(ManifoldConnectionHubRejectionReason::IdentityCollision);
            }
            if state.surfaces.len() >= MAX_SURFACES {
                return Err(ManifoldConnectionHubRejectionReason::CapacityExceeded);
            }
            state.surfaces.push(surface.clone());
            Ok(ApplyOutput::default())
        }
        ManifoldConnectionHubOperationRequest::UnregisterSurface {
            surface_id,
            provider_instance_id,
            reason,
        } => {
            let position = state
                .surfaces
                .iter()
                .position(|surface| {
                    &surface.surface_id == surface_id
                        && &surface.provider_instance_id == provider_instance_id
                })
                .ok_or(ManifoldConnectionHubRejectionReason::SurfaceNotActive)?;
            state.surfaces.remove(position);
            let mut output = ApplyOutput::default();
            cleanup_surface(state, surface_id, request, reason, &mut output)?;
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::Surface,
                surface_id.clone(),
                reason.clone(),
                request,
            )?;
            output.cleaned_subject_ids.push(surface_id.clone());
            sort_dedupe_ids(&mut output.cleaned_subject_ids);
            Ok(output)
        }
        ManifoldConnectionHubOperationRequest::AcquireSurfaceLease {
            lease_id,
            session_id,
            expected_transport_epoch,
            surface_id,
            requested_ttl_ms,
        } => {
            let session = active_session(state, session_id, request.requested_at_ms)?;
            if session.transport_epoch != *expected_transport_epoch {
                return Err(ManifoldConnectionHubRejectionReason::TransportEpochMismatch);
            }
            let surface = state
                .surfaces
                .iter()
                .find(|surface| &surface.surface_id == surface_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SurfaceNotActive)?;
            let provider = state
                .providers
                .iter()
                .find(|provider| provider.provider_instance_id == surface.provider_instance_id)
                .ok_or(ManifoldConnectionHubRejectionReason::ProviderNotActive)?;
            let parent_expiry = session.expires_at_ms.min(provider.admission_expires_at_ms);
            let expires_at_ms = checked_expiry(
                request.requested_at_ms,
                *requested_ttl_ms,
                policy.max_surface_lease_ttl_ms,
                Some(parent_expiry),
            )?;
            if state
                .surface_leases
                .iter()
                .any(|lease| &lease.lease_id == lease_id)
                || is_retired(
                    state,
                    ManifoldConnectionHubSubjectKind::SurfaceLease,
                    lease_id,
                )
            {
                return Err(ManifoldConnectionHubRejectionReason::IdentityCollision);
            }
            if state.surface_leases.len() >= MAX_SURFACE_LEASES {
                return Err(ManifoldConnectionHubRejectionReason::CapacityExceeded);
            }
            let lease = ManifoldConnectionHubSurfaceLease {
                schema_id: schema(SURFACE_LEASE_SCHEMA),
                lease_id: lease_id.clone(),
                session_id: session_id.clone(),
                controller_id: session.controller_id.clone(),
                surface_id: surface_id.clone(),
                provider_instance_id: surface.provider_instance_id.clone(),
                issued_transport_epoch: *expected_transport_epoch,
                issued_at_ms: request.requested_at_ms,
                expires_at_ms,
            };
            state.surface_leases.push(lease.clone());
            Ok(ApplyOutput {
                surface_lease: Some(lease),
                ..ApplyOutput::default()
            })
        }
        ManifoldConnectionHubOperationRequest::ReleaseSurfaceLease {
            lease_id,
            session_id,
            reason,
        } => {
            let position = state
                .surface_leases
                .iter()
                .position(|lease| &lease.lease_id == lease_id && &lease.session_id == session_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SurfaceLeaseNotActive)?;
            state.surface_leases.remove(position);
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::SurfaceLease,
                lease_id.clone(),
                reason.clone(),
                request,
            )?;
            Ok(ApplyOutput {
                cleaned_subject_ids: vec![lease_id.clone()],
                ..ApplyOutput::default()
            })
        }
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id,
            expected_transport_epoch,
            lease_id,
            command_id,
            typed_params_sha256,
        } => {
            if !is_sha256(typed_params_sha256) {
                return Err(ManifoldConnectionHubRejectionReason::InvalidTypedParamsDigest);
            }
            let session = active_session(state, session_id, request.requested_at_ms)?;
            if session.transport_epoch != *expected_transport_epoch {
                return Err(ManifoldConnectionHubRejectionReason::TransportEpochMismatch);
            }
            let controller = state
                .trusted_controllers
                .iter()
                .find(|controller| controller.controller_id == session.controller_id)
                .ok_or(ManifoldConnectionHubRejectionReason::ControllerNotTrusted)?;
            let lease = state
                .surface_leases
                .iter()
                .find(|lease| &lease.lease_id == lease_id && &lease.session_id == session_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SurfaceLeaseNotActive)?;
            if lease.expires_at_ms <= request.requested_at_ms {
                return Err(ManifoldConnectionHubRejectionReason::SurfaceLeaseNotActive);
            }
            let surface = state
                .surfaces
                .iter()
                .find(|surface| {
                    surface.surface_id == lease.surface_id
                        && surface.provider_instance_id == lease.provider_instance_id
                })
                .ok_or(ManifoldConnectionHubRejectionReason::SurfaceNotActive)?;
            let command = surface
                .commands
                .iter()
                .find(|command| &command.command_id == command_id)
                .ok_or(ManifoldConnectionHubRejectionReason::CommandNotRegistered)?;
            if !controller
                .capabilities
                .contains(&command.required_controller_capability)
            {
                return Err(ManifoldConnectionHubRejectionReason::ControllerCapabilityDenied);
            }
            let authorization = ManifoldConnectionHubCommandAuthorization {
                schema_id: schema(COMMAND_AUTHORIZATION_SCHEMA),
                authorization_id: command_authorization_id(
                    &request.request_id,
                    typed_params_sha256,
                    resulting_revision,
                ),
                request_id: request.request_id.clone(),
                session_id: session_id.clone(),
                transport_epoch: *expected_transport_epoch,
                lease_id: lease_id.clone(),
                surface_id: surface.surface_id.clone(),
                provider_instance_id: surface.provider_instance_id.clone(),
                provider_id: surface.provider_id.clone(),
                surface_contract_sha256: surface.surface_contract_sha256.clone(),
                command_id: command_id.clone(),
                required_controller_capability: command.required_controller_capability.clone(),
                typed_params_sha256: typed_params_sha256.clone(),
                proves_application_effect: false,
            };
            Ok(ApplyOutput {
                command_authorization: Some(authorization),
                ..ApplyOutput::default()
            })
        }
        ManifoldConnectionHubOperationRequest::RevokeSession { session_id, reason } => {
            let position = state
                .sessions
                .iter()
                .position(|session| &session.session_id == session_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SessionNotActive)?;
            state.sessions.remove(position);
            let mut output = ApplyOutput::default();
            cleanup_session(state, session_id, request, reason, &mut output)?;
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::Session,
                session_id.clone(),
                reason.clone(),
                request,
            )?;
            output.cleaned_subject_ids.push(session_id.clone());
            sort_dedupe_ids(&mut output.cleaned_subject_ids);
            Ok(output)
        }
        ManifoldConnectionHubOperationRequest::Expire => expire_state(state, request),
    }
}

fn validate_provider_admission(
    policy: &ManifoldConnectionHubPolicy,
    admission: &ManifoldAdmissionSnapshot,
    provider_id: &DottedId,
    provider_instance_id: &DottedId,
    use_request_id: &DottedId,
    now_ms: u64,
) -> Result<ManifoldConnectionHubProvider, ManifoldConnectionHubRejectionReason> {
    ManifoldAdmissionAuthority::from_snapshot(admission.clone())
        .map_err(|_| ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)?;
    let event = admission
        .audit_events
        .iter()
        .find(|event| {
            event.applied
                && event.operation == ManifoldAdmissionOperation::AuthorizeUse
                && &event.request_id == use_request_id
        })
        .ok_or(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)?;
    let binding = event
        .use_authorization
        .as_ref()
        .ok_or(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)?;
    if binding.request.capability_id.as_str() != PROVIDER_REGISTER_CAPABILITY
        || binding.request.identity != binding.token.identity
        || binding.token.expires_at_ms <= now_ms
        || !admission
            .active_tokens
            .iter()
            .any(|token| token == &binding.token)
    {
        return Err(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected);
    }
    let grant = policy
        .provider_grants
        .iter()
        .find(|grant| {
            &grant.provider_id == provider_id
                && grant.client_id == binding.token.identity.client_id
                && grant.client_lock_id == binding.token.client_lock_id
                && grant.client_lock_sha256 == binding.token.client_lock_fingerprint
        })
        .ok_or(ManifoldConnectionHubRejectionReason::ProviderAdmissionRejected)?;
    Ok(ManifoldConnectionHubProvider {
        schema_id: schema(PROVIDER_SCHEMA),
        provider_id: provider_id.clone(),
        provider_instance_id: provider_instance_id.clone(),
        identity: binding.token.identity.clone(),
        client_lock_id: binding.token.client_lock_id.clone(),
        client_lock_sha256: binding.token.client_lock_fingerprint.clone(),
        admission_authority_id: admission.authority_id.clone(),
        admission_authority_revision: admission.authority_revision,
        admission_use_request_id: use_request_id.clone(),
        admission_expires_at_ms: binding.token.expires_at_ms,
        surface_contract_sha256: grant.surface_contract_sha256.clone(),
        allowed_commands: grant.allowed_commands.clone(),
        registered_at_ms: now_ms,
    })
}

#[allow(clippy::too_many_lines)]
fn expire_state(
    state: &mut ManifoldConnectionHubState,
    request: &ManifoldConnectionHubRequest,
) -> Result<ApplyOutput, ManifoldConnectionHubRejectionReason> {
    let now = request.requested_at_ms;
    let reason = id("expired");
    let expired_controllers = state
        .trusted_controllers
        .iter()
        .filter(|controller| controller.expires_at_ms <= now)
        .map(|controller| controller.controller_id.clone())
        .collect::<Vec<_>>();
    let expired_sessions = state
        .sessions
        .iter()
        .filter(|session| session.expires_at_ms <= now)
        .map(|session| session.session_id.clone())
        .collect::<Vec<_>>();
    let expired_providers = state
        .providers
        .iter()
        .filter(|provider| provider.admission_expires_at_ms <= now)
        .map(|provider| provider.provider_instance_id.clone())
        .collect::<Vec<_>>();
    let expired_leases = state
        .surface_leases
        .iter()
        .filter(|lease| lease.expires_at_ms <= now)
        .map(|lease| lease.lease_id.clone())
        .collect::<Vec<_>>();
    if expired_controllers.is_empty()
        && expired_sessions.is_empty()
        && expired_providers.is_empty()
        && expired_leases.is_empty()
    {
        return Err(ManifoldConnectionHubRejectionReason::NothingExpired);
    }
    let mut output = ApplyOutput::default();
    for controller_id in expired_controllers {
        state
            .trusted_controllers
            .retain(|controller| controller.controller_id != controller_id);
        cleanup_controller(state, &controller_id, request, &reason, &mut output)?;
        tombstone(
            state,
            ManifoldConnectionHubSubjectKind::Controller,
            controller_id.clone(),
            reason.clone(),
            request,
        )?;
        output.cleaned_subject_ids.push(controller_id);
    }
    for session_id in expired_sessions {
        if state
            .sessions
            .iter()
            .any(|session| session.session_id == session_id)
        {
            state
                .sessions
                .retain(|session| session.session_id != session_id);
            cleanup_session(state, &session_id, request, &reason, &mut output)?;
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::Session,
                session_id.clone(),
                reason.clone(),
                request,
            )?;
            output.cleaned_subject_ids.push(session_id);
        }
    }
    for provider_instance_id in expired_providers {
        if state
            .providers
            .iter()
            .any(|provider| provider.provider_instance_id == provider_instance_id)
        {
            state
                .providers
                .retain(|provider| provider.provider_instance_id != provider_instance_id);
            cleanup_provider(state, &provider_instance_id, request, &reason, &mut output)?;
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::Provider,
                provider_instance_id.clone(),
                reason.clone(),
                request,
            )?;
            output.cleaned_subject_ids.push(provider_instance_id);
        }
    }
    for lease_id in expired_leases {
        if state
            .surface_leases
            .iter()
            .any(|lease| lease.lease_id == lease_id)
        {
            state
                .surface_leases
                .retain(|lease| lease.lease_id != lease_id);
            tombstone(
                state,
                ManifoldConnectionHubSubjectKind::SurfaceLease,
                lease_id.clone(),
                reason.clone(),
                request,
            )?;
            output.cleaned_subject_ids.push(lease_id);
        }
    }
    sort_dedupe_ids(&mut output.cleaned_subject_ids);
    Ok(output)
}

fn cleanup_controller(
    state: &mut ManifoldConnectionHubState,
    controller_id: &DottedId,
    request: &ManifoldConnectionHubRequest,
    reason: &DottedId,
    output: &mut ApplyOutput,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    let sessions = state
        .sessions
        .iter()
        .filter(|session| &session.controller_id == controller_id)
        .map(|session| session.session_id.clone())
        .collect::<Vec<_>>();
    for session_id in sessions {
        state
            .sessions
            .retain(|session| session.session_id != session_id);
        cleanup_session(state, &session_id, request, reason, output)?;
        tombstone(
            state,
            ManifoldConnectionHubSubjectKind::Session,
            session_id.clone(),
            reason.clone(),
            request,
        )?;
        output.cleaned_subject_ids.push(session_id);
    }
    Ok(())
}

fn cleanup_session(
    state: &mut ManifoldConnectionHubState,
    session_id: &DottedId,
    request: &ManifoldConnectionHubRequest,
    reason: &DottedId,
    output: &mut ApplyOutput,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    let leases = state
        .surface_leases
        .iter()
        .filter(|lease| &lease.session_id == session_id)
        .map(|lease| lease.lease_id.clone())
        .collect::<Vec<_>>();
    state
        .surface_leases
        .retain(|lease| &lease.session_id != session_id);
    for lease_id in leases {
        tombstone(
            state,
            ManifoldConnectionHubSubjectKind::SurfaceLease,
            lease_id.clone(),
            reason.clone(),
            request,
        )?;
        output.cleaned_subject_ids.push(lease_id);
    }
    Ok(())
}

fn cleanup_provider(
    state: &mut ManifoldConnectionHubState,
    provider_instance_id: &DottedId,
    request: &ManifoldConnectionHubRequest,
    reason: &DottedId,
    output: &mut ApplyOutput,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    let surfaces = state
        .surfaces
        .iter()
        .filter(|surface| &surface.provider_instance_id == provider_instance_id)
        .map(|surface| surface.surface_id.clone())
        .collect::<Vec<_>>();
    for surface_id in surfaces {
        state
            .surfaces
            .retain(|surface| surface.surface_id != surface_id);
        cleanup_surface(state, &surface_id, request, reason, output)?;
        tombstone(
            state,
            ManifoldConnectionHubSubjectKind::Surface,
            surface_id.clone(),
            reason.clone(),
            request,
        )?;
        output.cleaned_subject_ids.push(surface_id);
    }
    Ok(())
}

fn cleanup_surface(
    state: &mut ManifoldConnectionHubState,
    surface_id: &DottedId,
    request: &ManifoldConnectionHubRequest,
    reason: &DottedId,
    output: &mut ApplyOutput,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    let leases = state
        .surface_leases
        .iter()
        .filter(|lease| &lease.surface_id == surface_id)
        .map(|lease| lease.lease_id.clone())
        .collect::<Vec<_>>();
    state
        .surface_leases
        .retain(|lease| &lease.surface_id != surface_id);
    for lease_id in leases {
        tombstone(
            state,
            ManifoldConnectionHubSubjectKind::SurfaceLease,
            lease_id.clone(),
            reason.clone(),
            request,
        )?;
        output.cleaned_subject_ids.push(lease_id);
    }
    Ok(())
}

fn tombstone(
    state: &mut ManifoldConnectionHubState,
    subject_kind: ManifoldConnectionHubSubjectKind,
    subject_id: DottedId,
    reason: DottedId,
    request: &ManifoldConnectionHubRequest,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    if state.tombstones.len() >= MAX_TOMBSTONES {
        return Err(ManifoldConnectionHubRejectionReason::CapacityExceeded);
    }
    state.tombstones.push(ManifoldConnectionHubTombstone {
        subject_kind,
        subject_id,
        reason,
        request_id: request.request_id.clone(),
        retired_at_ms: request.requested_at_ms,
    });
    Ok(())
}

fn active_session<'a>(
    state: &'a ManifoldConnectionHubState,
    session_id: &DottedId,
    now_ms: u64,
) -> Result<&'a ManifoldConnectionHubSession, ManifoldConnectionHubRejectionReason> {
    state
        .sessions
        .iter()
        .find(|session| &session.session_id == session_id && session.expires_at_ms > now_ms)
        .ok_or(ManifoldConnectionHubRejectionReason::SessionNotActive)
}

fn require_operator(
    policy: &ManifoldConnectionHubPolicy,
    operator_evidence_id: &DottedId,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    if policy
        .trusted_operator_evidence_ids
        .contains(operator_evidence_id)
    {
        Ok(())
    } else {
        Err(ManifoldConnectionHubRejectionReason::OperatorNotTrusted)
    }
}

fn checked_expiry(
    now_ms: u64,
    ttl_ms: u64,
    policy_max_ms: u64,
    parent_expiry: Option<u64>,
) -> Result<u64, ManifoldConnectionHubRejectionReason> {
    if ttl_ms == 0 || ttl_ms > policy_max_ms {
        return Err(ManifoldConnectionHubRejectionReason::InvalidLifetime);
    }
    let expiry = now_ms
        .checked_add(ttl_ms)
        .ok_or(ManifoldConnectionHubRejectionReason::InvalidLifetime)?;
    if parent_expiry.is_some_and(|parent| expiry > parent) {
        return Err(ManifoldConnectionHubRejectionReason::InvalidLifetime);
    }
    Ok(expiry)
}

fn validate_transport(
    transport: &ManifoldConnectionHubTransportBinding,
    now_ms: u64,
) -> Result<(), ManifoldConnectionHubRejectionReason> {
    if transport.attached_at_ms != now_ms {
        return Err(ManifoldConnectionHubRejectionReason::TransportSubstitution);
    }
    Ok(())
}

fn rejected_receipt(
    request: &ManifoldConnectionHubRequest,
    operation: ManifoldConnectionHubOperation,
    revision: Revision,
    reason: ManifoldConnectionHubRejectionReason,
) -> ManifoldConnectionHubReceipt {
    ManifoldConnectionHubReceipt {
        schema_id: schema(RECEIPT_SCHEMA),
        receipt_id: artifact_id(
            "receipt.connection-hub.rejected",
            &request.request_id,
            revision.get(),
        ),
        request_id: request.request_id.clone(),
        operation,
        applied: false,
        prior_authority_revision: revision,
        resulting_authority_revision: revision,
        rejection_reason: Some(reason),
        session: None,
        surface_lease: None,
        command_authorization: None,
        cleaned_subject_ids: Vec::new(),
        audit_event: None,
    }
}

fn validate_policy(policy: &ManifoldConnectionHubPolicy) -> Result<(), ManifoldConnectionHubError> {
    if policy.schema_id.as_str() != POLICY_SCHEMA {
        return Err(ManifoldConnectionHubError::InvalidPolicy("schema_mismatch"));
    }
    if policy.trusted_operator_evidence_ids.is_empty()
        || !is_sorted_unique(&policy.trusted_operator_evidence_ids)
        || policy.allowed_controller_capabilities.is_empty()
        || policy.allowed_controller_capabilities.len() > MAX_CAPABILITIES
        || !is_sorted_unique(&policy.allowed_controller_capabilities)
        || policy.provider_grants.len() > MAX_PROVIDERS
        || !is_sorted_unique_by(&policy.provider_grants, |grant| &grant.provider_id)
    {
        return Err(ManifoldConnectionHubError::InvalidPolicy(
            "noncanonical_sets",
        ));
    }
    if policy.max_controller_ttl_ms == 0
        || policy.max_controller_ttl_ms > MAX_CONTROLLER_TTL_MS
        || policy.max_session_ttl_ms == 0
        || policy.max_session_ttl_ms > MAX_SESSION_TTL_MS
        || policy.max_surface_lease_ttl_ms == 0
        || policy.max_surface_lease_ttl_ms > MAX_SURFACE_LEASE_TTL_MS
    {
        return Err(ManifoldConnectionHubError::InvalidPolicy("unsafe_lifetime"));
    }
    for grant in &policy.provider_grants {
        if !is_sha256(&grant.client_lock_sha256)
            || !is_sha256(&grant.surface_contract_sha256)
            || grant.allowed_commands.is_empty()
            || grant.allowed_commands.len() > MAX_COMMANDS_PER_SURFACE
            || !is_sorted_unique_by(&grant.allowed_commands, |command| &command.command_id)
            || !grant.allowed_commands.iter().all(|command| {
                policy
                    .allowed_controller_capabilities
                    .contains(&command.required_controller_capability)
            })
        {
            return Err(ManifoldConnectionHubError::InvalidPolicy(
                "invalid_provider_grant",
            ));
        }
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &ManifoldConnectionHubSnapshot,
) -> Result<(), ManifoldConnectionHubError> {
    if snapshot.schema_id.as_str() != SNAPSHOT_SCHEMA {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "schema_mismatch",
        ));
    }
    validate_policy(&snapshot.policy)?;
    validate_state(&snapshot.policy, &snapshot.state)?;
    if snapshot.applied_request_ids.len() != snapshot.applied_request_sha256.len()
        || snapshot.applied_request_ids.len() != snapshot.audit_events.len()
        || snapshot.applied_request_ids.len() > MAX_REPLAY_RECORDS
        || !all_unique(&snapshot.applied_request_ids)
        || !all_unique(&snapshot.applied_request_sha256)
    {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "replay_lineage",
        ));
    }
    let expected_revision = u64::try_from(snapshot.audit_events.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .and_then(Revision::new)
        .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
            "revision_overflow",
        ))?;
    if snapshot.state.authority_revision != expected_revision {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "revision_lineage",
        ));
    }
    for (index, event) in snapshot.audit_events.iter().enumerate() {
        let sequence = u64::try_from(index + 1)
            .map_err(|_| ManifoldConnectionHubError::InvalidSnapshot("sequence_overflow"))?;
        let prior = Revision::new(sequence).ok_or(ManifoldConnectionHubError::InvalidSnapshot(
            "prior_revision",
        ))?;
        let resulting = prior
            .next()
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "resulting_revision",
            ))?;
        if event.schema_id.as_str() != AUDIT_SCHEMA
            || event.sequence != sequence
            || event.prior_authority_revision != prior
            || event.resulting_authority_revision != resulting
            || event.request.expected_authority_revision != prior
            || event.request.schema_id.as_str() != REQUEST_SCHEMA
            || event.operation != operation_label(&event.request.operation)
            || event.request_sha256 != typed_sha256(&event.request)
            || event.event_id
                != artifact_id("audit.connection-hub", &event.request.request_id, sequence)
            || snapshot.applied_request_ids[index] != event.request.request_id
            || snapshot.applied_request_sha256[index] != event.request_sha256
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "audit_substitution",
            ));
        }
    }
    let provider_use_ids = snapshot
        .audit_events
        .iter()
        .filter_map(|event| match &event.request.operation {
            ManifoldConnectionHubOperationRequest::RegisterProvider {
                admission_use_request_id,
                ..
            } => Some(admission_use_request_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !all_unique(&provider_use_ids) {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "provider_admission_replay",
        ));
    }
    if let Some(last) = snapshot.audit_events.last() {
        if last.resulting_state_sha256 != typed_sha256(&snapshot.state) {
            return Err(ManifoldConnectionHubError::InvalidSnapshot("state_digest"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_state(
    policy: &ManifoldConnectionHubPolicy,
    state: &ManifoldConnectionHubState,
) -> Result<(), ManifoldConnectionHubError> {
    if state.schema_id.as_str() != STATE_SCHEMA || state.authority_id != policy.authority_id {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "state_identity",
        ));
    }
    if state.trusted_controllers.len() > MAX_CONTROLLERS
        || state.sessions.len() > MAX_SESSIONS
        || state.providers.len() > MAX_PROVIDERS
        || state.surfaces.len() > MAX_SURFACES
        || state.surface_leases.len() > MAX_SURFACE_LEASES
        || state.tombstones.len() > MAX_TOMBSTONES
        || !is_sorted_unique_by(&state.trusted_controllers, |value| &value.controller_id)
        || !is_sorted_unique_by(&state.sessions, |value| &value.session_id)
        || !is_sorted_unique_by(&state.providers, |value| &value.provider_instance_id)
        || !is_sorted_unique_by(&state.surfaces, |value| &value.surface_id)
        || !is_sorted_unique_by(&state.surface_leases, |value| &value.lease_id)
    {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "state_bounds_or_order",
        ));
    }
    let mut live_ids = BTreeSet::new();
    for controller in &state.trusted_controllers {
        if !is_sha256(&controller.public_identity_sha256)
            || !is_sorted_unique(&controller.capabilities)
            || controller.capabilities.is_empty()
            || controller.trusted_at_ms >= controller.expires_at_ms
            || !controller
                .capabilities
                .iter()
                .all(|capability| policy.allowed_controller_capabilities.contains(capability))
            || !live_ids.insert(controller.controller_id.clone())
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "controller_damage",
            ));
        }
    }
    for session in &state.sessions {
        let parent = state
            .trusted_controllers
            .iter()
            .find(|controller| controller.controller_id == session.controller_id)
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "orphan_session",
            ))?;
        if session.schema_id.as_str() != SESSION_SCHEMA
            || session.transport_epoch == 0
            || session.opened_at_ms >= session.expires_at_ms
            || session.expires_at_ms > parent.expires_at_ms
            || session.transport.attached_at_ms < session.opened_at_ms
            || !live_ids.insert(session.session_id.clone())
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "session_damage",
            ));
        }
    }
    for provider in &state.providers {
        let grant = policy
            .provider_grants
            .iter()
            .find(|grant| {
                grant.provider_id == provider.provider_id
                    && grant.client_id == provider.identity.client_id
            })
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "provider_grant_missing",
            ))?;
        if provider.schema_id.as_str() != PROVIDER_SCHEMA
            || provider.client_lock_id != grant.client_lock_id
            || provider.client_lock_sha256 != grant.client_lock_sha256
            || provider.surface_contract_sha256 != grant.surface_contract_sha256
            || provider.allowed_commands != grant.allowed_commands
            || provider.registered_at_ms >= provider.admission_expires_at_ms
            || !live_ids.insert(provider.provider_instance_id.clone())
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "provider_damage",
            ));
        }
    }
    for surface in &state.surfaces {
        let provider = state
            .providers
            .iter()
            .find(|provider| {
                provider.provider_id == surface.provider_id
                    && provider.provider_instance_id == surface.provider_instance_id
            })
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "orphan_surface",
            ))?;
        if surface.schema_id.as_str() != SURFACE_SCHEMA
            || surface.display_label.is_empty()
            || surface.display_label.chars().count() > 96
            || surface.description.chars().count() > 160
            || !is_sha256(&surface.surface_contract_sha256)
            || surface.commands.is_empty()
            || surface.commands.len() > MAX_COMMANDS_PER_SURFACE
            || !is_sorted_unique_by(&surface.commands, |command| &command.command_id)
            || surface.surface_contract_sha256 != provider.surface_contract_sha256
            || surface.commands != provider.allowed_commands
            || !live_ids.insert(surface.surface_id.clone())
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "surface_damage",
            ));
        }
    }
    for lease in &state.surface_leases {
        let session = state
            .sessions
            .iter()
            .find(|session| session.session_id == lease.session_id)
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "orphan_lease_session",
            ))?;
        let surface = state
            .surfaces
            .iter()
            .find(|surface| surface.surface_id == lease.surface_id)
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "orphan_lease_surface",
            ))?;
        let provider = state
            .providers
            .iter()
            .find(|provider| provider.provider_instance_id == lease.provider_instance_id)
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "orphan_lease_provider",
            ))?;
        if lease.schema_id.as_str() != SURFACE_LEASE_SCHEMA
            || lease.controller_id != session.controller_id
            || lease.provider_instance_id != surface.provider_instance_id
            || lease.issued_transport_epoch == 0
            || lease.issued_transport_epoch > session.transport_epoch
            || lease.issued_at_ms >= lease.expires_at_ms
            || lease.expires_at_ms > session.expires_at_ms
            || lease.expires_at_ms > provider.admission_expires_at_ms
            || !live_ids.insert(lease.lease_id.clone())
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot("lease_damage"));
        }
    }
    let mut tombstone_keys = BTreeSet::new();
    for tombstone in &state.tombstones {
        let key = format!("{:?}:{}", tombstone.subject_kind, tombstone.subject_id);
        if !tombstone_keys.insert(key)
            || live_ids.contains(&tombstone.subject_id)
            || tombstone.retired_at_ms == 0
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "tombstone_damage",
            ));
        }
    }
    Ok(())
}

fn canonicalize_state(state: &mut ManifoldConnectionHubState) {
    state
        .trusted_controllers
        .sort_by(|left, right| left.controller_id.cmp(&right.controller_id));
    state
        .sessions
        .sort_by(|left, right| left.session_id.cmp(&right.session_id));
    state
        .providers
        .sort_by(|left, right| left.provider_instance_id.cmp(&right.provider_instance_id));
    state
        .surfaces
        .sort_by(|left, right| left.surface_id.cmp(&right.surface_id));
    state
        .surface_leases
        .sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
    state.tombstones.sort_by(|left, right| {
        format!("{:?}:{}", left.subject_kind, left.subject_id)
            .cmp(&format!("{:?}:{}", right.subject_kind, right.subject_id))
    });
}

fn is_retired(
    state: &ManifoldConnectionHubState,
    kind: ManifoldConnectionHubSubjectKind,
    id: &DottedId,
) -> bool {
    state
        .tombstones
        .iter()
        .any(|entry| entry.subject_kind == kind && &entry.subject_id == id)
}

fn owner_context_matches(
    request: &ManifoldConnectionHubRequest,
    owner_context: ManifoldConnectionHubOwnerContext<'_>,
) -> bool {
    if request.requested_at_ms != owner_context.observed_at_ms {
        return false;
    }
    match &request.operation {
        ManifoldConnectionHubOperationRequest::TrustController {
            operator_evidence_id,
            ..
        }
        | ManifoldConnectionHubOperationRequest::ForgetController {
            operator_evidence_id,
            ..
        } => {
            owner_context.verified_operator_evidence_id == Some(operator_evidence_id)
                && owner_context.admission_snapshot.is_none()
        }
        ManifoldConnectionHubOperationRequest::RegisterProvider { .. } => {
            owner_context.verified_operator_evidence_id.is_none()
                && owner_context.admission_snapshot.is_some()
        }
        _ => {
            owner_context.verified_operator_evidence_id.is_none()
                && owner_context.admission_snapshot.is_none()
        }
    }
}

fn operation_label(
    operation: &ManifoldConnectionHubOperationRequest,
) -> ManifoldConnectionHubOperation {
    match operation {
        ManifoldConnectionHubOperationRequest::TrustController { .. } => {
            ManifoldConnectionHubOperation::TrustController
        }
        ManifoldConnectionHubOperationRequest::ForgetController { .. } => {
            ManifoldConnectionHubOperation::ForgetController
        }
        ManifoldConnectionHubOperationRequest::OpenSession { .. } => {
            ManifoldConnectionHubOperation::OpenSession
        }
        ManifoldConnectionHubOperationRequest::ReplaceTransport { .. } => {
            ManifoldConnectionHubOperation::ReplaceTransport
        }
        ManifoldConnectionHubOperationRequest::RegisterProvider { .. } => {
            ManifoldConnectionHubOperation::RegisterProvider
        }
        ManifoldConnectionHubOperationRequest::UnregisterProvider { .. } => {
            ManifoldConnectionHubOperation::UnregisterProvider
        }
        ManifoldConnectionHubOperationRequest::RegisterSurface { .. } => {
            ManifoldConnectionHubOperation::RegisterSurface
        }
        ManifoldConnectionHubOperationRequest::UnregisterSurface { .. } => {
            ManifoldConnectionHubOperation::UnregisterSurface
        }
        ManifoldConnectionHubOperationRequest::AcquireSurfaceLease { .. } => {
            ManifoldConnectionHubOperation::AcquireSurfaceLease
        }
        ManifoldConnectionHubOperationRequest::ReleaseSurfaceLease { .. } => {
            ManifoldConnectionHubOperation::ReleaseSurfaceLease
        }
        ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand { .. } => {
            ManifoldConnectionHubOperation::AuthorizeSurfaceCommand
        }
        ManifoldConnectionHubOperationRequest::RevokeSession { .. } => {
            ManifoldConnectionHubOperation::RevokeSession
        }
        ManifoldConnectionHubOperationRequest::Expire => ManifoldConnectionHubOperation::Expire,
    }
}

fn is_terminal_cleanup_operation(operation: &ManifoldConnectionHubOperationRequest) -> bool {
    matches!(
        operation,
        ManifoldConnectionHubOperationRequest::ForgetController { .. }
            | ManifoldConnectionHubOperationRequest::UnregisterProvider { .. }
            | ManifoldConnectionHubOperationRequest::UnregisterSurface { .. }
            | ManifoldConnectionHubOperationRequest::ReleaseSurfaceLease { .. }
            | ManifoldConnectionHubOperationRequest::RevokeSession { .. }
            | ManifoldConnectionHubOperationRequest::Expire
    )
}

fn provider_admission_use_replayed(
    audit_events: &[ManifoldConnectionHubAuditEvent],
    operation: &ManifoldConnectionHubOperationRequest,
) -> bool {
    let ManifoldConnectionHubOperationRequest::RegisterProvider {
        admission_use_request_id,
        ..
    } = operation
    else {
        return false;
    };
    audit_events.iter().any(|event| {
        matches!(
            &event.request.operation,
            ManifoldConnectionHubOperationRequest::RegisterProvider {
                admission_use_request_id: applied,
                ..
            } if applied == admission_use_request_id
        )
    })
}

fn typed_sha256<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("typed serialization");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn artifact_id(prefix: &str, request_id: &DottedId, sequence: u64) -> DottedId {
    let digest = Sha256::digest(format!("{prefix}|{request_id}|{sequence}").as_bytes());
    let hex = format!("{digest:x}");
    DottedId::new(format!("{prefix}.{}", &hex[..16])).expect("derived id")
}

fn command_authorization_id(
    request_id: &DottedId,
    typed_params_sha256: &str,
    revision: Revision,
) -> DottedId {
    let digest = Sha256::digest(
        format!(
            "authorization.connection-hub|{request_id}|{typed_params_sha256}|{}",
            revision.get()
        )
        .as_bytes(),
    );
    let hex = format!("{digest:x}");
    DottedId::new(format!("authorization.connection-hub.{}", &hex[..16])).expect("derived id")
}

fn schema(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema")
}

fn id(value: &str) -> DottedId {
    DottedId::new(value).expect("static id")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn is_sorted_unique(values: &[DottedId]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_sorted_unique_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn all_unique<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn sort_dedupe_ids(values: &mut Vec<DottedId>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests;
