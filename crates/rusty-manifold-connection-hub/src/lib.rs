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
use rusty_manifold_broker_product::{ManifoldBrokerFeature, ManifoldBrokerProductLock};
use rusty_manifold_model::{DottedId, Revision, SchemaId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Authority policy schema.
pub const POLICY_SCHEMA: &str = "rusty.manifold.connection_hub.policy.v3";
/// Mutation request schema.
pub const REQUEST_SCHEMA: &str = "rusty.manifold.connection_hub.request.v3";
/// Accepted-state schema.
pub const STATE_SCHEMA: &str = "rusty.manifold.connection_hub.state.v3";
/// Restart snapshot schema.
pub const SNAPSHOT_SCHEMA: &str = "rusty.manifold.connection_hub.snapshot.v3";
/// Mutation receipt schema.
pub const RECEIPT_SCHEMA: &str = "rusty.manifold.connection_hub.receipt.v3";
/// Audit-event schema.
pub const AUDIT_SCHEMA: &str = "rusty.manifold.connection_hub.audit_event.v3";
/// Surface descriptor schema.
pub const SURFACE_SCHEMA: &str = "rusty.manifold.connection_hub.surface.v2";
/// Provider-admission record schema.
pub const PROVIDER_SCHEMA: &str = "rusty.manifold.connection_hub.provider.v2";
/// Logical session schema.
pub const SESSION_SCHEMA: &str = "rusty.manifold.connection_hub.session.v2";
/// Derivative surface-lease schema.
pub const SURFACE_LEASE_SCHEMA: &str = "rusty.manifold.connection_hub.surface_lease.v1";
/// Surface command-authorization schema.
pub const COMMAND_AUTHORIZATION_SCHEMA: &str =
    "rusty.manifold.connection_hub.command_authorization.v2";
/// Chained ordinary-work history checkpoint schema.
pub const HISTORY_CHECKPOINT_SCHEMA: &str = "rusty.manifold.connection_hub.history_checkpoint.v2";
/// Retained external-request replay-fence schema.
pub const EXTERNAL_REQUEST_FENCE_SCHEMA: &str =
    "rusty.manifold.connection_hub.external_request_fence.v1";
/// Cross-language canonical typed-parameter vector schema.
pub const TYPED_PARAMS_CANONICAL_VECTORS_SCHEMA: &str =
    "rusty.manifold.connection_hub.typed_params_canonical_vectors.v1";
/// Canonical empty-object parameter schema used by explicit zero-argument commands.
pub const EMPTY_TYPED_PARAMS_SCHEMA: &str = "rusty.manifold.connection_hub.typed_params.empty.v1";
/// SHA-256 of the exact committed empty typed-parameter schema bytes.
pub const EMPTY_TYPED_PARAMS_SCHEMA_SHA256: &str =
    "sha256:7eedc1ccca80b83dbd121d1e4bae4f6a6c9c1561e1a08d6d5919c668d5406a51";
/// SHA-256 of the canonical explicit zero-argument payload `{}`.
pub const EMPTY_TYPED_PARAMS_SHA256: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

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
const INITIAL_AUTHORITY_EPOCH: u64 = 1;

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
    /// Exact separately retained admission authority identity.
    pub admission_authority_id: DottedId,
    /// Exact standalone Broker product-lock identity.
    pub broker_product_lock_id: DottedId,
    /// Semantic fingerprint of the exact standalone Broker product lock.
    pub broker_product_lock_fingerprint: String,
    /// SHA-256 of the exact packaged standalone Broker product-lock bytes.
    pub broker_product_lock_sha256: String,
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
    /// Policy-fixed controller lifetime restored by one accepted authenticated
    /// activity. This is bounded by `max_controller_ttl_ms`.
    pub authenticated_activity_controller_ttl_ms: u64,
    /// Policy-fixed logical-session lifetime restored by one accepted
    /// authenticated activity. This is bounded by `max_session_ttl_ms` and by
    /// the refreshed controller lifetime.
    pub authenticated_activity_session_ttl_ms: u64,
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

/// One accepted external request digest retained while its logical session is
/// live. The adapter supplies the SHA-256 of the exact authenticated public
/// request bytes; Manifold never retains those bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubExternalRequestFence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact live logical session.
    pub session_id: DottedId,
    /// Exact trusted controller that authenticated the request.
    pub controller_id: DottedId,
    /// Greatest accepted external request sequence for this session. The
    /// additive Quest public command/keepalive v2 supplies this value; public
    /// v1 is not reinterpreted as sequence evidence.
    pub latest_external_request_sequence: u64,
    /// Lowercase SHA-256 of the exact latest external request bytes.
    pub latest_external_request_sha256: String,
    /// Internal accepted request identity that installed the high-water mark.
    pub latest_accepted_request_id: DottedId,
    /// Authority epoch in which the high-water mark was installed.
    pub latest_accepted_authority_epoch: u64,
    /// Trusted acceptance time.
    pub latest_accepted_at_ms: u64,
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
    /// Expiry of the one-use admission credential at registration. This is
    /// retained as provenance only; live provider lifetime is owned by the
    /// provider-process registration and explicit unregister/death cleanup.
    pub admission_credential_expires_at_ms: u64,
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
    /// Exact typed-parameter schema identity for this command.
    pub typed_params_schema_id: SchemaId,
    /// SHA-256 of the exact separately packaged typed-parameter schema bytes.
    pub typed_params_schema_sha256: String,
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
    /// Exact registered typed-parameter schema identity.
    pub typed_params_schema_id: SchemaId,
    /// SHA-256 of the exact registered typed-parameter schema bytes.
    pub typed_params_schema_sha256: String,
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
    /// Current ordinary-work namespace. It advances only through an audited
    /// owner-controlled history rollover.
    pub authority_epoch: u64,
    /// Revision at which the current epoch began. Current retained audit
    /// lineage starts immediately after this revision.
    pub epoch_started_at_revision: Revision,
    /// Admission events at or before this revision belong to an old Hub epoch
    /// and cannot register a new provider instance.
    pub admission_revision_floor: Revision,
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
    /// Bounded exact replay fences for authenticated external requests whose
    /// logical sessions remain live. These survive history rollover.
    pub external_request_fences: Vec<ManifoldConnectionHubExternalRequestFence>,
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
    /// Record one successfully authenticated activity and slide the exact
    /// controller and logical-session deadlines under fixed policy bounds.
    RefreshAuthenticatedActivity {
        /// Exact trusted controller authenticated by the adapter.
        controller_id: DottedId,
        /// Exact live logical session authenticated by the adapter.
        session_id: DottedId,
        /// Exact current physical transport epoch.
        expected_transport_epoch: u64,
        /// Monotonic external request sequence supplied by the additive public
        /// command/keepalive v2 contract.
        external_request_sequence: u64,
        /// SHA-256 of the exact external request bytes. The bytes are not
        /// retained by Manifold.
        external_request_sha256: String,
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
        /// Exact registered typed-parameter schema identity.
        typed_params_schema_id: SchemaId,
        /// SHA-256 of the exact registered typed-parameter schema bytes.
        typed_params_schema_sha256: String,
        /// SHA-256 of the exact canonical low-rate typed parameters.
        typed_params_sha256: String,
        /// Monotonic external request sequence supplied by the additive public
        /// command v2 contract.
        external_request_sequence: u64,
        /// SHA-256 of the exact authenticated public command request bytes.
        /// It is separately fenced across authority-history rollover.
        external_request_sha256: String,
    },
    /// Explicitly revoke one logical session and its derivative leases.
    RevokeSession {
        /// Logical session.
        session_id: DottedId,
        /// Low-sensitivity reason.
        reason: DottedId,
    },
    /// Compact the current ordinary-work audit epoch into one chained digest
    /// checkpoint without changing any live controller/session/provider/
    /// surface/lease record.
    RolloverHistory {
        /// Exact next authority epoch; must equal current epoch plus one.
        next_authority_epoch: u64,
        /// Exact current admission revision that fences old one-use grants.
        admission_authority_revision: Revision,
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
    /// Exact current authority epoch. Request ids are scoped to this epoch.
    pub authority_epoch: u64,
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
    /// Authenticated activity and sliding deadline refresh.
    RefreshAuthenticatedActivity,
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
    /// Audited ordinary-work history compaction and epoch advance.
    RolloverHistory,
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
    /// Exact authenticated external-request digest is malformed.
    InvalidExternalRequestDigest,
    /// External request sequence was zero, replayed, skipped, or otherwise
    /// differed from the exact next value retained for the logical session.
    ExternalRequestSequenceMismatch,
    /// Trusted activity time regressed behind the active transport or retained
    /// external request high-water mark.
    TrustedTimeRegression,
    /// Typed-parameter schema identity or exact schema bytes were substituted.
    TypedParamsSchemaMismatch,
    /// Request or newly created identity is outside the current epoch namespace.
    AuthorityEpochMismatch,
    /// History rollover was missing current admission-owner evidence or used an
    /// invalid successor epoch/revision.
    HistoryRolloverRejected,
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
    /// Authority epoch containing this event.
    pub authority_epoch: u64,
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

/// Constant-size chained checkpoint for one compacted ordinary-work epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldConnectionHubHistoryCheckpoint {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Compacted source authority epoch.
    pub source_authority_epoch: u64,
    /// Fresh successor authority epoch.
    pub resulting_authority_epoch: u64,
    /// Digest of the immediately preceding checkpoint, if any.
    pub prior_checkpoint_sha256: Option<String>,
    /// Cumulative accepted requests before the compacted epoch.
    pub prior_applied_request_count: u64,
    /// Requests compacted from the source epoch, including this rollover.
    pub source_epoch_applied_request_count: u64,
    /// Cumulative accepted requests through this checkpoint.
    pub resulting_applied_request_count: u64,
    /// Source epoch starting revision.
    pub source_epoch_started_at_revision: Revision,
    /// Global revision produced by this rollover.
    pub source_epoch_final_revision: Revision,
    /// Exact admission authority retained by policy.
    pub admission_authority_id: DottedId,
    /// Admission revision that fences all prior admission-use ids.
    pub admission_revision_floor: Revision,
    /// SHA-256 of the exact ordered source-epoch request-id vector.
    pub source_epoch_request_ids_sha256: String,
    /// SHA-256 of the exact ordered source-epoch request-digest vector.
    pub source_epoch_request_digests_sha256: String,
    /// SHA-256 of the exact retained active-session external-request fences at
    /// rollover. Individual digests remain addressable in accepted state.
    pub retained_external_request_fences_sha256: String,
    /// SHA-256 of the exact ordered source-epoch audit-event vector.
    pub source_epoch_audit_events_sha256: String,
    /// SHA-256 of exact compacted terminal tombstones.
    pub compacted_tombstones_sha256: String,
    /// SHA-256 of the exact resulting accepted state.
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
    /// Most recent constant-size chained history checkpoint.
    pub history_checkpoint: Option<ManifoldConnectionHubHistoryCheckpoint>,
    /// SHA-256 of the exact most recent checkpoint, absent before first rollover.
    pub history_checkpoint_sha256: Option<String>,
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
    /// Resulting trusted controller where authenticated activity refreshed it.
    pub trusted_controller: Option<ManifoldConnectionHubTrustedController>,
    /// Exact next external request sequence for the selected logical session.
    /// Authenticated transport replacement exposes it without consuming it;
    /// accepted commands and JSON keepalives consume one value.
    pub next_external_request_sequence: Option<u64>,
    /// Resulting surface lease where applicable.
    pub surface_lease: Option<ManifoldConnectionHubSurfaceLease>,
    /// Resulting one-time command authorization where applicable.
    pub command_authorization: Option<ManifoldConnectionHubCommandAuthorization>,
    /// Sorted identities removed as derivative cleanup.
    pub cleaned_subject_ids: Vec<DottedId>,
    /// Accepted audit event.
    pub audit_event: Option<ManifoldConnectionHubAuditEvent>,
    /// Accepted history checkpoint for a rollover, absent otherwise.
    pub history_checkpoint: Option<ManifoldConnectionHubHistoryCheckpoint>,
}

/// Non-serializable adapter evidence for one authenticated v2 command or JSON
/// keepalive. Holding the borrowed Hub owner is still required to apply it.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldConnectionHubAuthenticatedActivityEvidence<'a> {
    /// Trusted platform observation time.
    pub observed_at_ms: u64,
    /// Exact authenticated controller.
    pub controller_id: &'a DottedId,
    /// Exact authenticated logical session.
    pub session_id: &'a DottedId,
    /// Exact current physical transport epoch.
    pub transport_epoch: u64,
    /// Exact positive next public v2 request sequence.
    pub external_request_sequence: u64,
    /// Lowercase SHA-256 of the exact canonical public v2 request bytes.
    pub external_request_sha256: &'a str,
}

/// Non-serializable adapter evidence for one bearer-authenticated transport
/// replacement. Reconnect does not consume an external request sequence.
#[derive(Clone, Copy, Debug)]
pub struct ManifoldConnectionHubAuthenticatedTransportEvidence<'a> {
    /// Trusted platform observation time.
    pub observed_at_ms: u64,
    /// Exact authenticated controller.
    pub controller_id: &'a DottedId,
    /// Exact authenticated logical session.
    pub session_id: &'a DottedId,
    /// Exact transport epoch being replaced.
    pub transport_epoch: u64,
}

#[derive(Clone, Copy)]
enum ManifoldConnectionHubOwnerEvidence<'a> {
    Lifecycle {
        observed_at_ms: u64,
    },
    OperatorDecision {
        observed_at_ms: u64,
        verified_operator_evidence_id: &'a DottedId,
    },
    ProviderAdmission {
        observed_at_ms: u64,
        admission_authority: &'a ManifoldAdmissionAuthority,
    },
    HistoryRollover {
        observed_at_ms: u64,
        admission_authority: &'a ManifoldAdmissionAuthority,
    },
    AuthenticatedActivity(ManifoldConnectionHubAuthenticatedActivityEvidence<'a>),
    AuthenticatedTransport(ManifoldConnectionHubAuthenticatedTransportEvidence<'a>),
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
    /// Admission authority, Broker product lock, or packaged lock bytes do not
    /// match immutable Hub policy.
    OwnerBindingMismatch(&'static str),
}

impl fmt::Display for ManifoldConnectionHubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "{error}"),
            Self::SnapshotTooLarge => formatter.write_str("connection hub snapshot is too large"),
            Self::InvalidPolicy(reason) => write!(formatter, "invalid policy: {reason}"),
            Self::InvalidSnapshot(reason) => write!(formatter, "invalid snapshot: {reason}"),
            Self::OwnerBindingMismatch(reason) => {
                write!(formatter, "connection hub owner binding mismatch: {reason}")
            }
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
    pub fn new(
        policy: ManifoldConnectionHubPolicy,
        admission_authority: &ManifoldAdmissionAuthority,
        broker_product_lock: &ManifoldBrokerProductLock,
        packaged_broker_product_lock_bytes: &[u8],
    ) -> Result<Self, ManifoldConnectionHubError> {
        validate_policy(&policy)?;
        validate_owner_bindings(
            &policy,
            admission_authority,
            broker_product_lock,
            packaged_broker_product_lock_bytes,
        )?;
        let authority_id = policy.authority_id.clone();
        let admission_revision_floor = admission_authority.snapshot().authority_revision;
        Ok(Self {
            snapshot: ManifoldConnectionHubSnapshot {
                schema_id: schema(SNAPSHOT_SCHEMA),
                policy,
                state: ManifoldConnectionHubState {
                    schema_id: schema(STATE_SCHEMA),
                    authority_id,
                    authority_revision: Revision::INITIAL,
                    authority_epoch: INITIAL_AUTHORITY_EPOCH,
                    epoch_started_at_revision: Revision::INITIAL,
                    admission_revision_floor,
                    trusted_controllers: Vec::new(),
                    sessions: Vec::new(),
                    providers: Vec::new(),
                    surfaces: Vec::new(),
                    surface_leases: Vec::new(),
                    external_request_fences: Vec::new(),
                    tombstones: Vec::new(),
                },
                applied_request_ids: Vec::new(),
                applied_request_sha256: Vec::new(),
                audit_events: Vec::new(),
                history_checkpoint: None,
                history_checkpoint_sha256: None,
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
    pub fn restart_from_json(
        value: &str,
        admission_authority: &ManifoldAdmissionAuthority,
        broker_product_lock: &ManifoldBrokerProductLock,
        packaged_broker_product_lock_bytes: &[u8],
    ) -> Result<Self, ManifoldConnectionHubError> {
        if value.len() > MAX_SNAPSHOT_JSON_BYTES {
            return Err(ManifoldConnectionHubError::SnapshotTooLarge);
        }
        let snapshot: ManifoldConnectionHubSnapshot = serde_json::from_str(value)?;
        validate_snapshot(&snapshot)?;
        validate_owner_bindings(
            &snapshot.policy,
            admission_authority,
            broker_product_lock,
            packaged_broker_product_lock_bytes,
        )?;
        if admission_authority.snapshot().authority_revision
            < snapshot.state.admission_revision_floor
        {
            return Err(ManifoldConnectionHubError::OwnerBindingMismatch(
                "admission_revision_regressed",
            ));
        }
        Ok(Self { snapshot })
    }

    /// Borrows the only public mutation boundary. Evidence modes are created
    /// by its explicit methods and cannot be constructed or deserialized by a
    /// controller, provider, transport, or other crate.
    #[must_use]
    pub fn owner(&mut self) -> ManifoldConnectionHubOwner<'_> {
        ManifoldConnectionHubOwner { authority: self }
    }

    /// Applies one request with non-serializable evidence from the retained
    /// owner. Provider registration additionally requires that owner's exact
    /// current admission snapshot.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    fn apply_owned(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        owner_evidence: ManifoldConnectionHubOwnerEvidence<'_>,
    ) -> ManifoldConnectionHubReceipt {
        let operation = operation_label(&request.operation);
        let prior = self.snapshot.state.authority_revision;
        let source_epoch_started_at_revision = self.snapshot.state.epoch_started_at_revision;
        let request_digest = typed_sha256(request);
        let generic_rejection = if request.schema_id.as_str() != REQUEST_SCHEMA {
            Some(ManifoldConnectionHubRejectionReason::SchemaMismatch)
        } else if request.authority_epoch != self.snapshot.state.authority_epoch
            || !id_is_in_epoch(&request.request_id, request.authority_epoch)
        {
            Some(ManifoldConnectionHubRejectionReason::AuthorityEpochMismatch)
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
            || external_request_replayed(
                &self.snapshot.state.external_request_fences,
                &request.operation,
            )
            || provider_admission_use_replayed(&self.snapshot.audit_events, &request.operation)
        {
            Some(ManifoldConnectionHubRejectionReason::Replay)
        } else if !owner_evidence_matches(
            &self.snapshot.policy,
            &self.snapshot.state,
            request,
            owner_evidence,
        ) {
            Some(ManifoldConnectionHubRejectionReason::OwnerContextMismatch)
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
            owner_evidence.admission_snapshot(),
            resulting_revision,
        );
        let output = match outcome {
            Ok(output) => output,
            Err(reason) => return rejected_receipt(request, operation, prior, reason),
        };
        state.authority_revision = resulting_revision;
        let compacted_tombstones = if let ManifoldConnectionHubOperationRequest::RolloverHistory {
            next_authority_epoch,
            admission_authority_revision,
        } = &request.operation
        {
            let tombstones = state.tombstones.clone();
            state.tombstones.clear();
            state.authority_epoch = *next_authority_epoch;
            state.epoch_started_at_revision = resulting_revision;
            state.admission_revision_floor = *admission_authority_revision;
            Some(tombstones)
        } else {
            None
        };
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
            authority_epoch: request.authority_epoch,
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
        let history_checkpoint = compacted_tombstones.map(|tombstones| {
            let prior_applied_request_count = self
                .snapshot
                .history_checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.resulting_applied_request_count);
            let source_epoch_applied_request_count =
                u64::try_from(self.snapshot.applied_request_ids.len())
                    .expect("bounded replay count fits u64");
            let checkpoint = ManifoldConnectionHubHistoryCheckpoint {
                schema_id: schema(HISTORY_CHECKPOINT_SCHEMA),
                source_authority_epoch: request.authority_epoch,
                resulting_authority_epoch: self.snapshot.state.authority_epoch,
                prior_checkpoint_sha256: self.snapshot.history_checkpoint_sha256.clone(),
                prior_applied_request_count,
                source_epoch_applied_request_count,
                resulting_applied_request_count: prior_applied_request_count
                    .checked_add(source_epoch_applied_request_count)
                    .expect("accepted request count fits u64"),
                source_epoch_started_at_revision,
                source_epoch_final_revision: resulting_revision,
                admission_authority_id: self.snapshot.policy.admission_authority_id.clone(),
                admission_revision_floor: self.snapshot.state.admission_revision_floor,
                source_epoch_request_ids_sha256: typed_sha256(&self.snapshot.applied_request_ids),
                source_epoch_request_digests_sha256: typed_sha256(
                    &self.snapshot.applied_request_sha256,
                ),
                retained_external_request_fences_sha256: typed_sha256(
                    &self.snapshot.state.external_request_fences,
                ),
                source_epoch_audit_events_sha256: typed_sha256(&self.snapshot.audit_events),
                compacted_tombstones_sha256: typed_sha256(&tombstones),
                resulting_state_sha256: typed_sha256(&self.snapshot.state),
            };
            self.snapshot.history_checkpoint_sha256 = Some(typed_sha256(&checkpoint));
            self.snapshot.history_checkpoint = Some(checkpoint.clone());
            self.snapshot.applied_request_ids.clear();
            self.snapshot.applied_request_sha256.clear();
            self.snapshot.audit_events.clear();
            checkpoint
        });

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
            trusted_controller: output.trusted_controller,
            next_external_request_sequence: output.next_external_request_sequence,
            surface_lease: output.surface_lease,
            command_authorization: output.command_authorization,
            cleaned_subject_ids: output.cleaned_subject_ids,
            audit_event: Some(audit_event),
            history_checkpoint,
        }
    }
}

/// Sealed mutation boundary for one retained Connection Hub authority.
pub struct ManifoldConnectionHubOwner<'a> {
    authority: &'a mut ManifoldConnectionHubAuthority,
}

impl ManifoldConnectionHubOwner<'_> {
    /// Applies a lifecycle request using authority-owned platform time.
    #[must_use]
    pub fn apply_lifecycle(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        observed_at_ms: u64,
    ) -> ManifoldConnectionHubReceipt {
        self.authority.apply_owned(
            request,
            ManifoldConnectionHubOwnerEvidence::Lifecycle { observed_at_ms },
        )
    }

    /// Applies a trust decision using exact owner-verified operator evidence.
    #[must_use]
    pub fn apply_operator_decision(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        observed_at_ms: u64,
        verified_operator_evidence_id: &DottedId,
    ) -> ManifoldConnectionHubReceipt {
        self.authority.apply_owned(
            request,
            ManifoldConnectionHubOwnerEvidence::OperatorDecision {
                observed_at_ms,
                verified_operator_evidence_id,
            },
        )
    }

    /// Registers a provider only from the exact retained admission owner.
    #[must_use]
    pub fn register_provider(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        observed_at_ms: u64,
        admission_authority: &ManifoldAdmissionAuthority,
    ) -> ManifoldConnectionHubReceipt {
        self.authority.apply_owned(
            request,
            ManifoldConnectionHubOwnerEvidence::ProviderAdmission {
                observed_at_ms,
                admission_authority,
            },
        )
    }

    /// Applies one authenticated keepalive or surface-command request using
    /// exact adapter-proven controller, logical-session, transport-epoch, raw
    /// request-digest, and trusted-clock evidence.
    ///
    /// This is the Rust/JNI authority boundary for authenticated controller
    /// activity. The serialized request alone cannot select this evidence
    /// mode, and failed/replayed/stale activity never refreshes a deadline.
    #[must_use]
    pub fn apply_authenticated_activity(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        evidence: ManifoldConnectionHubAuthenticatedActivityEvidence<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.authority.apply_owned(
            request,
            ManifoldConnectionHubOwnerEvidence::AuthenticatedActivity(evidence),
        )
    }

    /// Replaces a bearer-authenticated transport without consuming the
    /// command/keepalive replay sequence. Successful replacement slides the
    /// exact controller/session deadlines and returns the next sequence so a
    /// reconnected client can safely resynchronize after a lost receipt.
    #[must_use]
    pub fn replace_authenticated_transport(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        evidence: ManifoldConnectionHubAuthenticatedTransportEvidence<'_>,
    ) -> ManifoldConnectionHubReceipt {
        self.authority.apply_owned(
            request,
            ManifoldConnectionHubOwnerEvidence::AuthenticatedTransport(evidence),
        )
    }

    /// Advances and compacts ordinary-work history with exact current
    /// admission-owner evidence.
    #[must_use]
    pub fn rollover_history(
        &mut self,
        request: &ManifoldConnectionHubRequest,
        observed_at_ms: u64,
        admission_authority: &ManifoldAdmissionAuthority,
    ) -> ManifoldConnectionHubReceipt {
        self.authority.apply_owned(
            request,
            ManifoldConnectionHubOwnerEvidence::HistoryRollover {
                observed_at_ms,
                admission_authority,
            },
        )
    }
}

impl ManifoldConnectionHubOwnerEvidence<'_> {
    const fn admission_snapshot(&self) -> Option<&ManifoldAdmissionSnapshot> {
        match self {
            Self::ProviderAdmission {
                admission_authority,
                ..
            }
            | Self::HistoryRollover {
                admission_authority,
                ..
            } => Some(admission_authority.snapshot()),
            Self::Lifecycle { .. }
            | Self::OperatorDecision { .. }
            | Self::AuthenticatedActivity(_)
            | Self::AuthenticatedTransport(_) => None,
        }
    }
}

#[derive(Default)]
struct ApplyOutput {
    session: Option<ManifoldConnectionHubSession>,
    trusted_controller: Option<ManifoldConnectionHubTrustedController>,
    next_external_request_sequence: Option<u64>,
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
            if !id_is_in_epoch(controller_id, state.authority_epoch)
                || !is_sha256(public_identity_sha256)
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
            if !id_is_in_epoch(session_id, state.authority_epoch) {
                return Err(ManifoldConnectionHubRejectionReason::AuthorityEpochMismatch);
            }
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
            let controller_id = state
                .sessions
                .iter()
                .find(|session| &session.session_id == session_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SessionNotActive)?
                .controller_id
                .clone();
            let (trusted_controller, _) = slide_authenticated_deadlines(
                policy,
                state,
                request.requested_at_ms,
                &controller_id,
                session_id,
                *expected_transport_epoch,
            )?;
            let session = state
                .sessions
                .iter_mut()
                .find(|session| &session.session_id == session_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SessionNotActive)?;
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
            let resulting_session = session.clone();
            let next_external_request_sequence = next_external_request_sequence(state, session_id)?;
            Ok(ApplyOutput {
                session: Some(resulting_session),
                trusted_controller: Some(trusted_controller),
                next_external_request_sequence: Some(next_external_request_sequence),
                ..ApplyOutput::default()
            })
        }
        ManifoldConnectionHubOperationRequest::RefreshAuthenticatedActivity {
            controller_id,
            session_id,
            expected_transport_epoch,
            external_request_sequence,
            external_request_sha256,
        } => {
            let (trusted_controller, session, next_external_request_sequence) =
                refresh_authenticated_deadlines(
                    policy,
                    state,
                    request,
                    ManifoldConnectionHubAuthenticatedActivityEvidence {
                        observed_at_ms: request.requested_at_ms,
                        controller_id,
                        session_id,
                        transport_epoch: *expected_transport_epoch,
                        external_request_sequence: *external_request_sequence,
                        external_request_sha256,
                    },
                )?;
            Ok(ApplyOutput {
                session: Some(session),
                trusted_controller: Some(trusted_controller),
                next_external_request_sequence: Some(next_external_request_sequence),
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
                state.admission_revision_floor,
            )?;
            if !id_is_in_epoch(provider_instance_id, state.authority_epoch) {
                return Err(ManifoldConnectionHubRejectionReason::AuthorityEpochMismatch);
            }
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
            if !id_is_in_epoch(&surface.surface_id, state.authority_epoch) {
                return Err(ManifoldConnectionHubRejectionReason::AuthorityEpochMismatch);
            }
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
            if !id_is_in_epoch(lease_id, state.authority_epoch) {
                return Err(ManifoldConnectionHubRejectionReason::AuthorityEpochMismatch);
            }
            let session = active_session(state, session_id, request.requested_at_ms)?;
            if session.transport_epoch != *expected_transport_epoch {
                return Err(ManifoldConnectionHubRejectionReason::TransportEpochMismatch);
            }
            let surface = state
                .surfaces
                .iter()
                .find(|surface| &surface.surface_id == surface_id)
                .ok_or(ManifoldConnectionHubRejectionReason::SurfaceNotActive)?;
            state
                .providers
                .iter()
                .find(|provider| provider.provider_instance_id == surface.provider_instance_id)
                .ok_or(ManifoldConnectionHubRejectionReason::ProviderNotActive)?;
            let expires_at_ms = checked_expiry(
                request.requested_at_ms,
                *requested_ttl_ms,
                policy.max_surface_lease_ttl_ms,
                Some(session.expires_at_ms),
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
            typed_params_schema_id,
            typed_params_schema_sha256,
            typed_params_sha256,
            external_request_sequence,
            external_request_sha256,
        } => {
            if !is_sha256(typed_params_schema_sha256) || !is_sha256(typed_params_sha256) {
                return Err(ManifoldConnectionHubRejectionReason::InvalidTypedParamsDigest);
            }
            if !is_sha256(external_request_sha256) {
                return Err(ManifoldConnectionHubRejectionReason::InvalidExternalRequestDigest);
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
            if &command.typed_params_schema_id != typed_params_schema_id
                || &command.typed_params_schema_sha256 != typed_params_schema_sha256
                || (command.typed_params_schema_id.as_str() == EMPTY_TYPED_PARAMS_SCHEMA
                    && typed_params_sha256 != EMPTY_TYPED_PARAMS_SHA256)
            {
                return Err(ManifoldConnectionHubRejectionReason::TypedParamsSchemaMismatch);
            }
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
                typed_params_schema_id: command.typed_params_schema_id.clone(),
                typed_params_schema_sha256: command.typed_params_schema_sha256.clone(),
                required_controller_capability: command.required_controller_capability.clone(),
                typed_params_sha256: typed_params_sha256.clone(),
                proves_application_effect: false,
            };
            let controller_id = session.controller_id.clone();
            let (trusted_controller, refreshed_session, next_external_request_sequence) =
                refresh_authenticated_deadlines(
                    policy,
                    state,
                    request,
                    ManifoldConnectionHubAuthenticatedActivityEvidence {
                        observed_at_ms: request.requested_at_ms,
                        controller_id: &controller_id,
                        session_id,
                        transport_epoch: *expected_transport_epoch,
                        external_request_sequence: *external_request_sequence,
                        external_request_sha256,
                    },
                )?;
            Ok(ApplyOutput {
                session: Some(refreshed_session),
                trusted_controller: Some(trusted_controller),
                next_external_request_sequence: Some(next_external_request_sequence),
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
        ManifoldConnectionHubOperationRequest::RolloverHistory {
            next_authority_epoch,
            admission_authority_revision,
        } => {
            let admission =
                admission.ok_or(ManifoldConnectionHubRejectionReason::HistoryRolloverRejected)?;
            if admission.authority_id != policy.admission_authority_id
                || admission.authority_revision != *admission_authority_revision
                || admission.authority_revision < state.admission_revision_floor
                || state.authority_epoch.checked_add(1) != Some(*next_authority_epoch)
            {
                return Err(ManifoldConnectionHubRejectionReason::HistoryRolloverRejected);
            }
            Ok(ApplyOutput::default())
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
    admission_revision_floor: Revision,
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
    if admission.authority_id != policy.admission_authority_id
        || admission.authority_revision < admission_revision_floor
        || event.resulting_authority_revision <= admission_revision_floor
        || binding.request.capability_id.as_str() != PROVIDER_REGISTER_CAPABILITY
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
        admission_credential_expires_at_ms: binding.token.expires_at_ms,
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
    let expired_leases = state
        .surface_leases
        .iter()
        .filter(|lease| lease.expires_at_ms <= now)
        .map(|lease| lease.lease_id.clone())
        .collect::<Vec<_>>();
    if expired_controllers.is_empty() && expired_sessions.is_empty() && expired_leases.is_empty() {
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
    state
        .external_request_fences
        .retain(|fence| &fence.session_id != session_id);
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

fn refresh_authenticated_deadlines(
    policy: &ManifoldConnectionHubPolicy,
    state: &mut ManifoldConnectionHubState,
    request: &ManifoldConnectionHubRequest,
    evidence: ManifoldConnectionHubAuthenticatedActivityEvidence<'_>,
) -> Result<
    (
        ManifoldConnectionHubTrustedController,
        ManifoldConnectionHubSession,
        u64,
    ),
    ManifoldConnectionHubRejectionReason,
> {
    if !is_sha256(evidence.external_request_sha256) {
        return Err(ManifoldConnectionHubRejectionReason::InvalidExternalRequestDigest);
    }
    let fence_position = state
        .external_request_fences
        .iter()
        .position(|fence| &fence.session_id == evidence.session_id);
    let expected_external_request_sequence = match fence_position {
        Some(position) => {
            if request.requested_at_ms
                < state.external_request_fences[position].latest_accepted_at_ms
            {
                return Err(ManifoldConnectionHubRejectionReason::TrustedTimeRegression);
            }
            state.external_request_fences[position]
                .latest_external_request_sequence
                .checked_add(1)
                .ok_or(ManifoldConnectionHubRejectionReason::ExternalRequestSequenceMismatch)?
        }
        None => 1,
    };
    if evidence.external_request_sequence != expected_external_request_sequence {
        return Err(ManifoldConnectionHubRejectionReason::ExternalRequestSequenceMismatch);
    }
    let (controller, session) = slide_authenticated_deadlines(
        policy,
        state,
        evidence.observed_at_ms,
        evidence.controller_id,
        evidence.session_id,
        evidence.transport_epoch,
    )?;
    let fence = ManifoldConnectionHubExternalRequestFence {
        schema_id: schema(EXTERNAL_REQUEST_FENCE_SCHEMA),
        session_id: evidence.session_id.clone(),
        controller_id: evidence.controller_id.clone(),
        latest_external_request_sequence: evidence.external_request_sequence,
        latest_external_request_sha256: evidence.external_request_sha256.to_owned(),
        latest_accepted_request_id: request.request_id.clone(),
        latest_accepted_authority_epoch: request.authority_epoch,
        latest_accepted_at_ms: request.requested_at_ms,
    };
    if let Some(position) = fence_position {
        state.external_request_fences[position] = fence;
    } else {
        state.external_request_fences.push(fence);
    }
    Ok((
        controller,
        session,
        evidence
            .external_request_sequence
            .checked_add(1)
            .ok_or(ManifoldConnectionHubRejectionReason::ExternalRequestSequenceMismatch)?,
    ))
}

fn slide_authenticated_deadlines(
    policy: &ManifoldConnectionHubPolicy,
    state: &mut ManifoldConnectionHubState,
    observed_at_ms: u64,
    controller_id: &DottedId,
    session_id: &DottedId,
    expected_transport_epoch: u64,
) -> Result<
    (
        ManifoldConnectionHubTrustedController,
        ManifoldConnectionHubSession,
    ),
    ManifoldConnectionHubRejectionReason,
> {
    let controller_position = state
        .trusted_controllers
        .iter()
        .position(|controller| &controller.controller_id == controller_id)
        .ok_or(ManifoldConnectionHubRejectionReason::ControllerNotTrusted)?;
    let session_position = state
        .sessions
        .iter()
        .position(|session| &session.session_id == session_id)
        .ok_or(ManifoldConnectionHubRejectionReason::SessionNotActive)?;
    let controller = &state.trusted_controllers[controller_position];
    let session = &state.sessions[session_position];
    if controller.expires_at_ms <= observed_at_ms {
        return Err(ManifoldConnectionHubRejectionReason::ControllerNotTrusted);
    }
    if session.controller_id != *controller_id || session.expires_at_ms <= observed_at_ms {
        return Err(ManifoldConnectionHubRejectionReason::SessionNotActive);
    }
    if session.transport_epoch != expected_transport_epoch {
        return Err(ManifoldConnectionHubRejectionReason::TransportEpochMismatch);
    }
    if observed_at_ms < session.transport.attached_at_ms {
        return Err(ManifoldConnectionHubRejectionReason::TrustedTimeRegression);
    }
    let controller_expires_at_ms = checked_expiry(
        observed_at_ms,
        policy.authenticated_activity_controller_ttl_ms,
        policy.max_controller_ttl_ms,
        None,
    )?;
    let session_expires_at_ms = checked_expiry(
        observed_at_ms,
        policy.authenticated_activity_session_ttl_ms,
        policy.max_session_ttl_ms,
        Some(controller_expires_at_ms),
    )?;
    state.trusted_controllers[controller_position].expires_at_ms = state.trusted_controllers
        [controller_position]
        .expires_at_ms
        .max(controller_expires_at_ms);
    state.sessions[session_position].expires_at_ms = state.sessions[session_position]
        .expires_at_ms
        .max(session_expires_at_ms);
    Ok((
        state.trusted_controllers[controller_position].clone(),
        state.sessions[session_position].clone(),
    ))
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
        trusted_controller: None,
        next_external_request_sequence: None,
        surface_lease: None,
        command_authorization: None,
        cleaned_subject_ids: Vec::new(),
        audit_event: None,
        history_checkpoint: None,
    }
}

fn validate_policy(policy: &ManifoldConnectionHubPolicy) -> Result<(), ManifoldConnectionHubError> {
    if policy.schema_id.as_str() != POLICY_SCHEMA {
        return Err(ManifoldConnectionHubError::InvalidPolicy("schema_mismatch"));
    }
    if !is_product_lock_fingerprint(&policy.broker_product_lock_fingerprint)
        || !is_sha256(&policy.broker_product_lock_sha256)
        || policy.trusted_operator_evidence_ids.is_empty()
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
        || policy.authenticated_activity_controller_ttl_ms == 0
        || policy.authenticated_activity_controller_ttl_ms > policy.max_controller_ttl_ms
        || policy.authenticated_activity_session_ttl_ms == 0
        || policy.authenticated_activity_session_ttl_ms > policy.max_session_ttl_ms
        || policy.authenticated_activity_session_ttl_ms
            > policy.authenticated_activity_controller_ttl_ms
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
                is_sha256(&command.typed_params_schema_sha256)
                    && policy
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

fn validate_owner_bindings(
    policy: &ManifoldConnectionHubPolicy,
    admission_authority: &ManifoldAdmissionAuthority,
    broker_product_lock: &ManifoldBrokerProductLock,
    packaged_broker_product_lock_bytes: &[u8],
) -> Result<(), ManifoldConnectionHubError> {
    if admission_authority.snapshot().authority_id != policy.admission_authority_id {
        return Err(ManifoldConnectionHubError::OwnerBindingMismatch(
            "admission_authority_id",
        ));
    }
    let decoded_lock: ManifoldBrokerProductLock =
        serde_json::from_slice(packaged_broker_product_lock_bytes).map_err(|_| {
            ManifoldConnectionHubError::OwnerBindingMismatch("broker_product_lock_bytes")
        })?;
    if &decoded_lock != broker_product_lock
        || !broker_product_lock.standalone_enabled
        || broker_product_lock.embedded_enabled
        || !broker_product_lock
            .features
            .contains(&ManifoldBrokerFeature::ConnectionHub)
        || broker_product_lock.lock_id != policy.broker_product_lock_id
        || broker_product_lock.spec_fingerprint != policy.broker_product_lock_fingerprint
        || typed_bytes_sha256(packaged_broker_product_lock_bytes)
            != policy.broker_product_lock_sha256
    {
        return Err(ManifoldConnectionHubError::OwnerBindingMismatch(
            "broker_product_lock",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
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
    match (
        &snapshot.history_checkpoint,
        &snapshot.history_checkpoint_sha256,
    ) {
        (None, None) => {
            if snapshot.state.authority_epoch != INITIAL_AUTHORITY_EPOCH
                || snapshot.state.epoch_started_at_revision != Revision::INITIAL
            {
                return Err(ManifoldConnectionHubError::InvalidSnapshot(
                    "initial_epoch_lineage",
                ));
            }
        }
        (Some(checkpoint), Some(checkpoint_sha256)) => {
            if checkpoint.schema_id.as_str() != HISTORY_CHECKPOINT_SCHEMA
                || checkpoint.source_epoch_applied_request_count == 0
                || checkpoint.source_authority_epoch.checked_add(1)
                    != Some(checkpoint.resulting_authority_epoch)
                || checkpoint.resulting_authority_epoch != snapshot.state.authority_epoch
                || checkpoint.source_epoch_final_revision
                    != snapshot.state.epoch_started_at_revision
                || checkpoint.admission_authority_id != snapshot.policy.admission_authority_id
                || checkpoint.admission_revision_floor != snapshot.state.admission_revision_floor
                || checkpoint
                    .prior_applied_request_count
                    .checked_add(checkpoint.source_epoch_applied_request_count)
                    != Some(checkpoint.resulting_applied_request_count)
                || !is_sha256(&checkpoint.source_epoch_request_ids_sha256)
                || !is_sha256(&checkpoint.source_epoch_request_digests_sha256)
                || !is_sha256(&checkpoint.retained_external_request_fences_sha256)
                || !is_sha256(&checkpoint.source_epoch_audit_events_sha256)
                || !is_sha256(&checkpoint.compacted_tombstones_sha256)
                || !is_sha256(&checkpoint.resulting_state_sha256)
                || checkpoint_sha256 != &typed_sha256(checkpoint)
            {
                return Err(ManifoldConnectionHubError::InvalidSnapshot(
                    "history_checkpoint",
                ));
            }
        }
        _ => {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "history_checkpoint_pair",
            ));
        }
    }
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
        .and_then(|count| count.checked_add(snapshot.state.epoch_started_at_revision.get()))
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
        let prior = snapshot
            .state
            .epoch_started_at_revision
            .get()
            .checked_add(sequence - 1)
            .and_then(Revision::new)
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "prior_revision",
            ))?;
        let resulting = prior
            .next()
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "resulting_revision",
            ))?;
        if event.schema_id.as_str() != AUDIT_SCHEMA
            || event.sequence != sequence
            || event.authority_epoch != snapshot.state.authority_epoch
            || event.prior_authority_revision != prior
            || event.resulting_authority_revision != resulting
            || event.request.expected_authority_revision != prior
            || event.request.schema_id.as_str() != REQUEST_SCHEMA
            || event.request.authority_epoch != snapshot.state.authority_epoch
            || !id_is_in_epoch(&event.request.request_id, event.request.authority_epoch)
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
    } else if let Some(checkpoint) = &snapshot.history_checkpoint {
        if checkpoint.resulting_state_sha256 != typed_sha256(&snapshot.state) {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "checkpoint_state_digest",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_state(
    policy: &ManifoldConnectionHubPolicy,
    state: &ManifoldConnectionHubState,
) -> Result<(), ManifoldConnectionHubError> {
    if state.schema_id.as_str() != STATE_SCHEMA
        || state.authority_id != policy.authority_id
        || state.authority_epoch == 0
        || state.epoch_started_at_revision > state.authority_revision
    {
        return Err(ManifoldConnectionHubError::InvalidSnapshot(
            "state_identity",
        ));
    }
    if state.trusted_controllers.len() > MAX_CONTROLLERS
        || state.sessions.len() > MAX_SESSIONS
        || state.providers.len() > MAX_PROVIDERS
        || state.surfaces.len() > MAX_SURFACES
        || state.surface_leases.len() > MAX_SURFACE_LEASES
        || state.external_request_fences.len() > MAX_SESSIONS
        || state.tombstones.len() > MAX_TOMBSTONES
        || !is_sorted_unique_by(&state.trusted_controllers, |value| &value.controller_id)
        || !is_sorted_unique_by(&state.sessions, |value| &value.session_id)
        || !is_sorted_unique_by(&state.providers, |value| &value.provider_instance_id)
        || !is_sorted_unique_by(&state.surfaces, |value| &value.surface_id)
        || !is_sorted_unique_by(&state.surface_leases, |value| &value.lease_id)
        || !is_sorted_unique_by(&state.external_request_fences, |value| &value.session_id)
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
            || !id_is_in_or_before_epoch(&controller.controller_id, state.authority_epoch)
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
            || !id_is_in_or_before_epoch(&session.session_id, state.authority_epoch)
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
            || provider.admission_authority_id != policy.admission_authority_id
            || provider.surface_contract_sha256 != grant.surface_contract_sha256
            || provider.allowed_commands != grant.allowed_commands
            || provider.registered_at_ms >= provider.admission_credential_expires_at_ms
            || !id_is_in_or_before_epoch(&provider.provider_instance_id, state.authority_epoch)
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
            || !id_is_in_or_before_epoch(&surface.surface_id, state.authority_epoch)
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
        let _provider = state
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
            || !id_is_in_or_before_epoch(&lease.lease_id, state.authority_epoch)
            || !live_ids.insert(lease.lease_id.clone())
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot("lease_damage"));
        }
    }
    for fence in &state.external_request_fences {
        let session = state
            .sessions
            .iter()
            .find(|session| session.session_id == fence.session_id)
            .ok_or(ManifoldConnectionHubError::InvalidSnapshot(
                "orphan_external_request_fence_session",
            ))?;
        if fence.schema_id.as_str() != EXTERNAL_REQUEST_FENCE_SCHEMA
            || fence.controller_id != session.controller_id
            || fence.latest_external_request_sequence == 0
            || !is_sha256(&fence.latest_external_request_sha256)
            || fence.latest_accepted_authority_epoch == 0
            || fence.latest_accepted_authority_epoch > state.authority_epoch
            || fence.latest_accepted_at_ms < session.opened_at_ms
            || !id_is_in_or_before_epoch(&fence.latest_accepted_request_id, state.authority_epoch)
        {
            return Err(ManifoldConnectionHubError::InvalidSnapshot(
                "external_request_fence_damage",
            ));
        }
    }
    let mut tombstone_keys = BTreeSet::new();
    for tombstone in &state.tombstones {
        let key = format!("{:?}:{}", tombstone.subject_kind, tombstone.subject_id);
        if !tombstone_keys.insert(key)
            || live_ids.contains(&tombstone.subject_id)
            || tombstone.retired_at_ms == 0
            || !id_is_in_or_before_epoch(&tombstone.subject_id, state.authority_epoch)
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
    state
        .external_request_fences
        .sort_by(|left, right| left.session_id.cmp(&right.session_id));
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

#[allow(clippy::too_many_lines)]
fn owner_evidence_matches(
    policy: &ManifoldConnectionHubPolicy,
    state: &ManifoldConnectionHubState,
    request: &ManifoldConnectionHubRequest,
    owner_evidence: ManifoldConnectionHubOwnerEvidence<'_>,
) -> bool {
    let observed_at_ms = match owner_evidence {
        ManifoldConnectionHubOwnerEvidence::Lifecycle { observed_at_ms }
        | ManifoldConnectionHubOwnerEvidence::OperatorDecision { observed_at_ms, .. }
        | ManifoldConnectionHubOwnerEvidence::ProviderAdmission { observed_at_ms, .. }
        | ManifoldConnectionHubOwnerEvidence::HistoryRollover { observed_at_ms, .. } => {
            observed_at_ms
        }
        ManifoldConnectionHubOwnerEvidence::AuthenticatedActivity(evidence) => {
            evidence.observed_at_ms
        }
        ManifoldConnectionHubOwnerEvidence::AuthenticatedTransport(evidence) => {
            evidence.observed_at_ms
        }
    };
    if request.requested_at_ms != observed_at_ms {
        return false;
    }
    match (&request.operation, owner_evidence) {
        (
            ManifoldConnectionHubOperationRequest::TrustController {
                operator_evidence_id,
                ..
            }
            | ManifoldConnectionHubOperationRequest::ForgetController {
                operator_evidence_id,
                ..
            },
            ManifoldConnectionHubOwnerEvidence::OperatorDecision {
                verified_operator_evidence_id,
                ..
            },
        ) => verified_operator_evidence_id == operator_evidence_id,
        (
            ManifoldConnectionHubOperationRequest::RegisterProvider { .. },
            ManifoldConnectionHubOwnerEvidence::ProviderAdmission {
                admission_authority,
                ..
            },
        )
        | (
            ManifoldConnectionHubOperationRequest::RolloverHistory { .. },
            ManifoldConnectionHubOwnerEvidence::HistoryRollover {
                admission_authority,
                ..
            },
        ) => admission_authority.snapshot().authority_id == policy.admission_authority_id,
        (
            ManifoldConnectionHubOperationRequest::RefreshAuthenticatedActivity {
                controller_id,
                session_id,
                expected_transport_epoch,
                external_request_sequence,
                external_request_sha256,
            },
            ManifoldConnectionHubOwnerEvidence::AuthenticatedActivity(evidence),
        ) => {
            controller_id == evidence.controller_id
                && session_id == evidence.session_id
                && expected_transport_epoch == &evidence.transport_epoch
                && external_request_sequence == &evidence.external_request_sequence
                && external_request_sha256 == evidence.external_request_sha256
        }
        (
            ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
                session_id,
                expected_transport_epoch,
                external_request_sequence,
                external_request_sha256,
                ..
            },
            ManifoldConnectionHubOwnerEvidence::AuthenticatedActivity(evidence),
        ) => {
            session_id == evidence.session_id
                && expected_transport_epoch == &evidence.transport_epoch
                && external_request_sequence == &evidence.external_request_sequence
                && external_request_sha256 == evidence.external_request_sha256
                && state.sessions.iter().any(|session| {
                    &session.session_id == evidence.session_id
                        && &session.controller_id == evidence.controller_id
                })
        }
        (
            ManifoldConnectionHubOperationRequest::ReplaceTransport {
                session_id,
                expected_transport_epoch,
                ..
            },
            ManifoldConnectionHubOwnerEvidence::AuthenticatedTransport(evidence),
        ) => {
            session_id == evidence.session_id
                && expected_transport_epoch == &evidence.transport_epoch
                && state.sessions.iter().any(|session| {
                    &session.session_id == evidence.session_id
                        && &session.controller_id == evidence.controller_id
                })
        }
        (
            ManifoldConnectionHubOperationRequest::TrustController { .. }
            | ManifoldConnectionHubOperationRequest::ForgetController { .. }
            | ManifoldConnectionHubOperationRequest::RegisterProvider { .. }
            | ManifoldConnectionHubOperationRequest::RolloverHistory { .. }
            | ManifoldConnectionHubOperationRequest::ReplaceTransport { .. }
            | ManifoldConnectionHubOperationRequest::RefreshAuthenticatedActivity { .. }
            | ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand { .. },
            _,
        ) => false,
        (_, ManifoldConnectionHubOwnerEvidence::Lifecycle { .. }) => true,
        _ => false,
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
        ManifoldConnectionHubOperationRequest::RefreshAuthenticatedActivity { .. } => {
            ManifoldConnectionHubOperation::RefreshAuthenticatedActivity
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
        ManifoldConnectionHubOperationRequest::RolloverHistory { .. } => {
            ManifoldConnectionHubOperation::RolloverHistory
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
            | ManifoldConnectionHubOperationRequest::RolloverHistory { .. }
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

fn external_request_replayed(
    fences: &[ManifoldConnectionHubExternalRequestFence],
    operation: &ManifoldConnectionHubOperationRequest,
) -> bool {
    let (session_id, sequence, digest) = match operation {
        ManifoldConnectionHubOperationRequest::RefreshAuthenticatedActivity {
            session_id,
            external_request_sequence,
            external_request_sha256,
            ..
        }
        | ManifoldConnectionHubOperationRequest::AuthorizeSurfaceCommand {
            session_id,
            external_request_sequence,
            external_request_sha256,
            ..
        } => (
            session_id,
            *external_request_sequence,
            external_request_sha256,
        ),
        _ => return false,
    };
    fences.iter().any(|fence| {
        &fence.session_id == session_id
            && (sequence <= fence.latest_external_request_sequence
                || digest == &fence.latest_external_request_sha256)
    })
}

fn next_external_request_sequence(
    state: &ManifoldConnectionHubState,
    session_id: &DottedId,
) -> Result<u64, ManifoldConnectionHubRejectionReason> {
    state
        .external_request_fences
        .iter()
        .find(|fence| &fence.session_id == session_id)
        .map_or(Ok(1), |fence| {
            fence
                .latest_external_request_sequence
                .checked_add(1)
                .ok_or(ManifoldConnectionHubRejectionReason::ExternalRequestSequenceMismatch)
        })
}

fn typed_sha256<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("typed serialization");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn typed_bytes_sha256(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn is_product_lock_fingerprint(value: &str) -> bool {
    value.len() == 24
        && value.starts_with("fnv1a64-")
        && value[8..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn id_is_in_epoch(value: &DottedId, epoch: u64) -> bool {
    value.as_str().starts_with(&format!("epoch-{epoch}."))
}

fn id_is_in_or_before_epoch(value: &DottedId, current_epoch: u64) -> bool {
    value
        .as_str()
        .strip_prefix("epoch-")
        .and_then(|tail| tail.split_once('.'))
        .and_then(|(epoch, _)| epoch.parse::<u64>().ok())
        .is_some_and(|epoch| epoch > 0 && epoch <= current_epoch)
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
