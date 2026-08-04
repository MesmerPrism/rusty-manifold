//! Platform-neutral authority for a bounded local control surface.
//!
//! This crate owns admission, a single controller lease, command acceptance,
//! replay, expiry, and revocation composition. It does not open a listener,
//! verify a plaintext pairing code, execute application effects, or claim that
//! a Runtime Host acceptance receipt proves a player effect.

use rusty_manifold_admission::{
    ManifoldAdmissionAdministrativeRevocationRequest, ManifoldAdmissionAuthority,
    ManifoldAdmissionReceipt, ManifoldAdmissionRequest, ManifoldAdmissionUseRequest,
    ManifoldClientIdentity, ADMISSION_ADMINISTRATIVE_REVOCATION_REQUEST_SCHEMA,
    ADMISSION_REQUEST_SCHEMA, ADMISSION_USE_REQUEST_SCHEMA,
};
use rusty_manifold_model::{
    DottedId, ManifoldAuthoritySnapshot, ManifoldClockSnapshot, ManifoldControlLease,
    ManifoldControlLeaseAuthorityApplication, ManifoldControlLeaseAuthorityApplicationOutcome,
    ManifoldControlLeaseRequest, ManifoldControlLeaseRevocationAuthorityApplication,
    ManifoldControlLeaseRevocationAuthorityApplicationOutcome,
    ManifoldControlLeaseRevocationRequest, Revision, SafetyClass, SchemaId,
};
use rusty_manifold_runtime_host::{
    ManifoldRuntimeApplicationReceipt, ManifoldRuntimeCommandRequest,
    ManifoldRuntimeControlLeaseAdoptionReceipt, ManifoldRuntimeControlLeaseAdoptionRequest,
    ManifoldRuntimeControlLeaseAuthorityApplication, ManifoldRuntimeDispatchReceipt,
    ManifoldRuntimeHost, ManifoldRuntimeTypedParamsDigest, HOST_COMMAND_REQUEST_SCHEMA,
    HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Local-control policy schema.
pub const LOCAL_CONTROL_POLICY_SCHEMA: &str = "rusty.manifold.local_control.policy.v1";
/// Pairing-window request schema.
pub const LOCAL_CONTROL_WINDOW_REQUEST_SCHEMA: &str =
    "rusty.manifold.local_control.window_request.v1";
/// Pairing-window receipt schema.
pub const LOCAL_CONTROL_WINDOW_RECEIPT_SCHEMA: &str =
    "rusty.manifold.local_control.window_receipt.v1";
/// Pairing evidence schema.
pub const LOCAL_CONTROL_CONTROLLER_EVIDENCE_SCHEMA: &str =
    "rusty.manifold.local_control.controller_evidence.v1";
/// Controller admission request schema.
pub const LOCAL_CONTROL_ADMISSION_REQUEST_SCHEMA: &str =
    "rusty.manifold.local_control.admission_request.v1";
/// Controller admission receipt schema.
pub const LOCAL_CONTROL_ADMISSION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.local_control.admission_receipt.v1";
/// Command request schema.
pub const LOCAL_CONTROL_COMMAND_REQUEST_SCHEMA: &str =
    "rusty.manifold.local_control.command_request.v1";
/// Command acceptance receipt schema.
pub const LOCAL_CONTROL_COMMAND_RECEIPT_SCHEMA: &str =
    "rusty.manifold.local_control.command_receipt.v1";
/// Controller revocation request schema.
pub const LOCAL_CONTROL_REVOCATION_REQUEST_SCHEMA: &str =
    "rusty.manifold.local_control.revocation_request.v1";
/// Controller revocation receipt schema.
pub const LOCAL_CONTROL_REVOCATION_RECEIPT_SCHEMA: &str =
    "rusty.manifold.local_control.revocation_receipt.v1";
/// Explicit expiry request schema.
pub const LOCAL_CONTROL_EXPIRY_REQUEST_SCHEMA: &str =
    "rusty.manifold.local_control.expiry_request.v1";
/// Explicit expiry receipt schema.
pub const LOCAL_CONTROL_EXPIRY_RECEIPT_SCHEMA: &str =
    "rusty.manifold.local_control.expiry_receipt.v1";
/// Wearer/adapter disable request schema.
pub const LOCAL_CONTROL_DISABLE_REQUEST_SCHEMA: &str =
    "rusty.manifold.local_control.disable_request.v1";
/// Wearer/adapter disable receipt schema.
pub const LOCAL_CONTROL_DISABLE_RECEIPT_SCHEMA: &str =
    "rusty.manifold.local_control.disable_receipt.v1";
/// Display-safe status schema.
pub const LOCAL_CONTROL_SAFE_STATUS_SCHEMA: &str = "rusty.manifold.local_control.safe_status.v1";

const MAX_COMMANDS: usize = 64;
const MAX_REPLAY_IDS: usize = 4_096;
const MAX_WINDOW_TTL_MS: u64 = 10 * 60 * 1_000;
const MAX_SESSION_TTL_MS: u64 = 60 * 60 * 1_000;
const MAX_IDLE_TIMEOUT_MS: u64 = 15 * 60 * 1_000;
const MAX_RATE_WINDOW_MS: u64 = 60_000;
const MAX_RATE_LIMIT: u16 = 120;

/// One command in the closed, build-time local-control registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlCommandDescriptor {
    /// Exact command id.
    pub command_id: DottedId,
    /// Admission capability required for this command.
    pub capability_id: DottedId,
    /// Single-controller lease scope required for mutating commands.
    pub required_lease_scope: Option<DottedId>,
    /// Exact typed parameter contract, or `None` for an empty payload.
    pub params_type_id: Option<DottedId>,
    /// Bounded command safety class.
    pub safety_class: SafetyClass,
}

/// Immutable policy for one local-control authority instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlPolicy {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Exact local-control authority id.
    pub authority_id: DottedId,
    /// Exact trusted adapter that verifies pairing and transport facts.
    pub trusted_adapter_id: DottedId,
    /// Exact platform-verified installed adapter identity.
    ///
    /// This is the Quest package/signing identity, not a fabricated browser or
    /// Apple signing identity.
    pub adapter_identity: ManifoldClientIdentity,
    /// Non-secret logical identity for the one paired browser controller.
    pub controller_id: DottedId,
    /// Lease scope held by the sole admitted controller.
    pub controller_lease_scope: DottedId,
    /// Capability used to acquire that controller lease.
    pub controller_lease_capability_id: DottedId,
    /// Closed command registry.
    pub commands: Vec<ManifoldLocalControlCommandDescriptor>,
    /// Maximum wearer-opened pairing window.
    pub max_window_ttl_ms: u64,
    /// Maximum admitted controller session.
    pub max_session_ttl_ms: u64,
    /// Controller idle timeout.
    pub idle_timeout_ms: u64,
    /// Exact sliding rate window.
    pub rate_window_ms: u64,
    /// Maximum command attempts in the rate window.
    pub max_commands_per_window: u16,
    /// Whether the trusted platform adapter may identify an ADB shell operator
    /// in a debug-only build instead of a wearer action.
    #[serde(default)]
    pub allow_debug_shell_operator: bool,
}

/// How the adapter conveyed the same mandatory single-use pairing code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldLocalControlPairingPresentation {
    /// User entered the code manually.
    ManualEntry,
    /// A QR code conveyed the code as an optional convenience.
    QrConvenience,
    /// No pairing code was used because the wearer explicitly opened the
    /// separately labelled unauthenticated LAN mode.
    OpenLanInsecure,
}

/// Wearer-selected authentication posture for one bounded listener window.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldLocalControlAccessMode {
    /// A manually entered single-use code authenticates the controller.
    #[default]
    Paired,
    /// Any LAN peer may claim the one controller lease without authentication.
    OpenLanInsecure,
}

/// Trusted foreground actor that explicitly requested a bounded listener.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldLocalControlEnableActor {
    /// A wearer selected the mode from the visible headset panel.
    #[default]
    Wearer,
    /// Android's shell UID called the debug-only, DUMP-protected provider.
    DebugShell,
}

/// Sanitized adapter evidence that a single-use code was verified.
///
/// The code and any derived bearer material are deliberately absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControllerEvidence {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use evidence id.
    pub evidence_id: DottedId,
    /// Trusted adapter that performed verification.
    pub adapter_id: DottedId,
    /// Exact wearer-opened pairing window.
    pub window_id: DottedId,
    /// Exact non-secret logical controller identity.
    pub controller_id: DottedId,
    /// How the mandatory code was presented.
    pub presentation: ManifoldLocalControlPairingPresentation,
    /// Adapter assertion that the single-use code matched.
    pub pairing_code_verified: bool,
    /// Trusted observation time.
    pub observed_at_ms: u64,
    /// Evidence expiry.
    pub expires_at_ms: u64,
}

/// Wearer-authorized request to open one bounded pairing window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlWindowRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use request id.
    pub request_id: DottedId,
    /// New window id.
    pub window_id: DottedId,
    /// Explicit wearer-selected authentication posture.
    #[serde(default)]
    pub access_mode: ManifoldLocalControlAccessMode,
    /// Exact foreground actor asserted by the trusted platform adapter.
    #[serde(default)]
    pub enable_actor: ManifoldLocalControlEnableActor,
    /// Expected local-control revision.
    pub expected_local_revision: Revision,
    /// Trusted open time.
    pub opened_at_ms: u64,
    /// Bounded window expiry.
    pub expires_at_ms: u64,
    /// Sanitized wearer confirmation evidence.
    pub wearer_evidence_id: DottedId,
}

/// Receipt for one pairing-window open attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlWindowReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit composite receipt id.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// Exact requested window id.
    pub window_id: DottedId,
    /// Exact access mode reviewed for this window.
    pub access_mode: ManifoldLocalControlAccessMode,
    /// Exact actor reviewed for this window.
    pub enable_actor: ManifoldLocalControlEnableActor,
    /// Whether the pairing window opened.
    pub opened: bool,
    /// Exact resulting composite revision tuple.
    pub resulting_revisions: ManifoldLocalControlRevisionTuple,
    /// Display-safe resulting status.
    pub status: ManifoldLocalControlSafeStatus,
    /// Stable rejection.
    pub rejection_reason: Option<ManifoldLocalControlRejectionReason>,
}

/// Request to admit the one controller proven by pairing evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlAdmissionRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use composite request id.
    pub request_id: DottedId,
    /// Expected local-control revision.
    pub expected_local_revision: Revision,
    /// Expected admission authority revision.
    pub expected_admission_revision: Revision,
    /// Expected generic Manifold authority revision.
    pub expected_lease_authority_revision: Revision,
    /// Expected Runtime Host authority revision.
    pub expected_host_revision: Revision,
    /// Sanitized pairing verification evidence.
    pub evidence: ManifoldLocalControllerEvidence,
    /// Trusted request time.
    pub requested_at_ms: u64,
    /// Requested session lifetime.
    pub requested_session_ttl_ms: u64,
}

/// Composite receipt for one controller admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlAdmissionReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit composite receipt id.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// Whether all three authorities accepted the controller atomically.
    pub admitted: bool,
    /// Exact resulting composite revision tuple.
    pub resulting_revisions: ManifoldLocalControlRevisionTuple,
    /// Admission token issuance receipt, when attempted.
    pub admission: Option<ManifoldAdmissionReceipt>,
    /// Generic lease application, when attempted.
    pub lease_application: Option<ManifoldControlLeaseAuthorityApplication>,
    /// Runtime Host lease adoption, when attempted.
    pub host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    /// Stable composite rejection.
    pub rejection_reason: Option<ManifoldLocalControlRejectionReason>,
}

/// One closed-registry command request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlCommandRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use request id retained against replay.
    pub request_id: DottedId,
    /// Expected local-control revision.
    pub expected_local_revision: Revision,
    /// Expected admission authority revision.
    pub expected_admission_revision: Revision,
    /// Expected Runtime Host authority revision.
    pub expected_host_revision: Revision,
    /// Exact opaque token id obtained from admission.
    pub token_id: DottedId,
    /// Closed-registry command id.
    pub command_id: DottedId,
    /// Canonical typed parameters, when the registry requires them.
    pub params_digest: Option<ManifoldRuntimeTypedParamsDigest>,
    /// Trusted issue time.
    pub issued_at_ms: u64,
    /// Short command expiry.
    pub expires_at_ms: u64,
}

/// Composite receipt proving command acceptance, never application effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlCommandReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit composite receipt id.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// Closed command id.
    pub command_id: DottedId,
    /// Whether admission and Runtime Host accepted the command.
    pub command_accepted: bool,
    /// Exact controller lease selected by an admitted command.
    pub controller_lease_id: Option<DottedId>,
    /// Exact resulting composite revision tuple.
    pub resulting_revisions: ManifoldLocalControlRevisionTuple,
    /// Always false: application effect belongs to the app/player owner.
    pub proves_application_effect: bool,
    /// Admission capability-use receipt, when attempted.
    pub admission_use: Option<ManifoldAdmissionReceipt>,
    /// Runtime Host review receipt, when attempted.
    pub dispatch: Option<ManifoldRuntimeDispatchReceipt>,
    /// Runtime Host accepted-state application receipt, when attempted.
    pub application: Option<ManifoldRuntimeApplicationReceipt>,
    /// Stable composite rejection.
    pub rejection_reason: Option<ManifoldLocalControlRejectionReason>,
}

/// Wearer/authority request to revoke the active controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlRevocationRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use composite request id.
    pub request_id: DottedId,
    /// Expected local-control revision.
    pub expected_local_revision: Revision,
    /// Expected admission authority revision.
    pub expected_admission_revision: Revision,
    /// Expected generic lease authority revision.
    pub expected_lease_authority_revision: Revision,
    /// Expected Runtime Host authority revision.
    pub expected_host_revision: Revision,
    /// Stable, display-safe reason.
    pub reason: DottedId,
    /// Trusted request time.
    pub requested_at_ms: u64,
    /// Sanitized wearer/authority evidence.
    pub evidence_id: DottedId,
}

/// Composite receipt for authority-owned controller revocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlRevocationReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit composite receipt id.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// Whether admission, lease authority, and Runtime Host all revoked.
    pub revoked: bool,
    /// Exact resulting composite revision tuple.
    pub resulting_revisions: ManifoldLocalControlRevisionTuple,
    /// Authority-owned admission revocation receipt, when attempted.
    pub admission_revocation: Option<ManifoldAdmissionReceipt>,
    /// Generic lease revocation application, when attempted.
    pub lease_revocation: Option<ManifoldControlLeaseRevocationAuthorityApplication>,
    /// Runtime Host lease-removal adoption, when attempted.
    pub host_adoption: Option<ManifoldRuntimeControlLeaseAdoptionReceipt>,
    /// Stable composite rejection.
    pub rejection_reason: Option<ManifoldLocalControlRejectionReason>,
}

/// Explicit request to enforce session or idle expiry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlExpiryRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use composite request id.
    pub request_id: DottedId,
    /// Expected local-control revision.
    pub expected_local_revision: Revision,
    /// Expected admission authority revision.
    pub expected_admission_revision: Revision,
    /// Expected generic lease authority revision.
    pub expected_lease_authority_revision: Revision,
    /// Expected Runtime Host authority revision.
    pub expected_host_revision: Revision,
    /// Trusted sweep time.
    pub requested_at_ms: u64,
    /// Sanitized clock/timer evidence.
    pub evidence_id: DottedId,
}

/// Receipt for an explicit session/idle expiry enforcement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlExpiryReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit composite receipt id.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// Whether expiry terminally revoked the controller.
    pub expired: bool,
    /// Exact resulting composite revision tuple.
    pub resulting_revisions: ManifoldLocalControlRevisionTuple,
    /// Exact authority revocation used to enforce expiry.
    pub revocation: Option<ManifoldLocalControlRevocationReceipt>,
    /// Stable composite rejection.
    pub rejection_reason: Option<ManifoldLocalControlRejectionReason>,
}

/// Request to return either an open window or active controller to disabled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlDisableRequest {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// One-use composite request id.
    pub request_id: DottedId,
    /// Expected local-control revision.
    pub expected_local_revision: Revision,
    /// Expected admission authority revision.
    pub expected_admission_revision: Revision,
    /// Expected generic lease authority revision.
    pub expected_lease_authority_revision: Revision,
    /// Expected Runtime Host authority revision.
    pub expected_host_revision: Revision,
    /// Stable reason such as wearer revoke or listener start failure.
    pub reason: DottedId,
    /// Trusted request time.
    pub requested_at_ms: u64,
    /// Sanitized wearer/adapter evidence.
    pub evidence_id: DottedId,
}

/// Receipt proving that local control returned to disabled state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlDisableReceipt {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Explicit composite receipt id.
    pub receipt_id: DottedId,
    /// Source request.
    pub request_id: DottedId,
    /// State observed before the operation.
    pub prior_state: ManifoldLocalControlState,
    /// Whether the authority is now disabled.
    pub disabled: bool,
    /// Exact resulting composite revision tuple.
    pub resulting_revisions: ManifoldLocalControlRevisionTuple,
    /// Terminal controller revocation when a controller was active.
    pub revocation: Option<ManifoldLocalControlRevocationReceipt>,
    /// Stable composite rejection.
    pub rejection_reason: Option<ManifoldLocalControlRejectionReason>,
}

/// Coarse, display-safe local-control lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldLocalControlState {
    /// No pairing window and no controller.
    Disabled,
    /// A wearer-opened pairing window is active.
    PairingWindowOpen,
    /// Exactly one controller is admitted.
    ControllerActive,
}

/// Exact revisions enclosed by one composite local-control revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlRevisionTuple {
    /// Composite local-control revision.
    pub local_revision: Revision,
    /// Admission authority revision.
    pub admission_revision: Revision,
    /// Generic lease authority revision.
    pub lease_authority_revision: Revision,
    /// Runtime Host authority revision.
    pub host_revision: Revision,
}

/// Status safe to expose to the local web UI or wearer display.
///
/// It contains no pairing code, token id, signing digest, URL, or credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifoldLocalControlSafeStatus {
    /// Schema identifier.
    #[serde(rename = "$schema")]
    pub schema_id: SchemaId,
    /// Coarse lifecycle state.
    pub state: ManifoldLocalControlState,
    /// Active wearer-selected mode, absent only while disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<ManifoldLocalControlAccessMode>,
    /// Actor that opened the active window/controller admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_actor: Option<ManifoldLocalControlEnableActor>,
    /// Local-control revision.
    pub local_revision: Revision,
    /// Admission authority revision.
    pub admission_revision: Revision,
    /// Generic lease authority revision.
    pub lease_authority_revision: Revision,
    /// Runtime Host authority revision.
    pub host_revision: Revision,
    /// Pairing window id, while open.
    pub window_id: Option<DottedId>,
    /// Pairing window expiry, while open.
    pub window_expires_at_ms: Option<u64>,
    /// Public controller id, while active.
    pub controller_id: Option<DottedId>,
    /// Absolute session expiry, while active.
    pub session_expires_at_ms: Option<u64>,
    /// Absolute idle deadline, while active.
    pub idle_expires_at_ms: Option<u64>,
    /// Last accepted command receipt id.
    pub last_accepted_command_receipt_id: Option<DottedId>,
}

/// Stable rejection for composite local-control decisions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifoldLocalControlRejectionReason {
    /// Request or policy schema mismatch.
    SchemaMismatch,
    /// Request expected an older local-control revision.
    StaleLocalRevision,
    /// Request expected an older admission authority revision.
    StaleAdmissionRevision,
    /// Request expected an older generic lease authority revision.
    StaleLeaseAuthorityRevision,
    /// Request expected an older Runtime Host revision.
    StaleHostRevision,
    /// Listener/pairing window is disabled.
    Disabled,
    /// Pairing window or request has expired.
    Expired,
    /// Pairing proof was not exact, fresh, and code-verified.
    PairingEvidenceInvalid,
    /// One controller is already active.
    ControllerAlreadyActive,
    /// No controller is active.
    NoActiveController,
    /// Token or exact controller identity did not match the active controller.
    ControllerMismatch,
    /// Request id was already reviewed.
    ReplayedRequest,
    /// Strict command rate limit was reached.
    RateLimited,
    /// Command is absent from the closed registry.
    UnknownCommand,
    /// Typed payload shape does not match the registered command.
    InvalidTypedParams,
    /// Requested lifetime violates policy.
    InvalidLifetime,
    /// Expiry enforcement ran before either deadline.
    NotExpired,
    /// A composing authority rejected the request.
    AuthorityRejected,
    /// A composing contract invariant failed.
    AuthorityInvariant,
    /// Bounded replay/audit capacity was exhausted.
    AuthorityCapacityExhausted,
}

/// Construction or invariant failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldLocalControlError {
    reason: &'static str,
}

impl ManifoldLocalControlError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for ManifoldLocalControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "local-control authority invalid: {}",
            self.reason
        )
    }
}

impl std::error::Error for ManifoldLocalControlError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PairingWindow {
    window_id: DottedId,
    expires_at_ms: u64,
    access_mode: ManifoldLocalControlAccessMode,
    enable_actor: ManifoldLocalControlEnableActor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveController {
    token_id: DottedId,
    lease: ManifoldControlLease,
    session_expires_at_ms: u64,
    idle_expires_at_ms: u64,
    access_mode: ManifoldLocalControlAccessMode,
    enable_actor: ManifoldLocalControlEnableActor,
}

/// Composite source-only authority. Construction is disabled by default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldLocalControlAuthority {
    policy: ManifoldLocalControlPolicy,
    local_revision: Revision,
    admission: ManifoldAdmissionAuthority,
    lease_authority: ManifoldAuthoritySnapshot,
    runtime_host: ManifoldRuntimeHost,
    window: Option<PairingWindow>,
    controller: Option<ActiveController>,
    reviewed_request_ids: Vec<DottedId>,
    command_attempt_times_ms: Vec<u64>,
    last_accepted_command_receipt_id: Option<DottedId>,
}

impl ManifoldLocalControlAuthority {
    /// Constructs a disabled authority from three exact accepted snapshots.
    ///
    /// # Errors
    ///
    /// Rejects misaligned authority identities, command registries, capabilities,
    /// lease scopes, or invalid policy bounds.
    pub fn new(
        policy: ManifoldLocalControlPolicy,
        admission: ManifoldAdmissionAuthority,
        lease_authority: ManifoldAuthoritySnapshot,
        runtime_host: ManifoldRuntimeHost,
    ) -> Result<Self, ManifoldLocalControlError> {
        validate_policy(&policy, &admission, &lease_authority, &runtime_host)?;
        Ok(Self {
            policy,
            local_revision: Revision::INITIAL,
            admission,
            lease_authority,
            runtime_host,
            window: None,
            controller: None,
            reviewed_request_ids: Vec::new(),
            command_attempt_times_ms: Vec::new(),
            last_accepted_command_receipt_id: None,
        })
    }

    /// Returns the immutable closed-registry policy.
    #[must_use]
    pub const fn policy(&self) -> &ManifoldLocalControlPolicy {
        &self.policy
    }

    /// Returns the exact lower-authority revisions enclosed by local revision.
    #[must_use]
    pub fn revision_tuple(&self) -> ManifoldLocalControlRevisionTuple {
        ManifoldLocalControlRevisionTuple {
            local_revision: self.local_revision,
            admission_revision: self.admission.snapshot().authority_revision,
            lease_authority_revision: self.lease_authority.authority_revision,
            host_revision: self.runtime_host.snapshot().authority_revision,
        }
    }

    /// Returns display-safe state without bearer material.
    #[must_use]
    pub fn safe_status(&self) -> ManifoldLocalControlSafeStatus {
        let state = if self.controller.is_some() {
            ManifoldLocalControlState::ControllerActive
        } else if self.window.is_some() {
            ManifoldLocalControlState::PairingWindowOpen
        } else {
            ManifoldLocalControlState::Disabled
        };
        let revisions = self.revision_tuple();
        ManifoldLocalControlSafeStatus {
            schema_id: schema_id(LOCAL_CONTROL_SAFE_STATUS_SCHEMA),
            state,
            access_mode: self
                .window
                .as_ref()
                .map(|window| window.access_mode)
                .or_else(|| {
                    self.controller
                        .as_ref()
                        .map(|controller| controller.access_mode)
                }),
            enable_actor: self
                .window
                .as_ref()
                .map(|window| window.enable_actor)
                .or_else(|| {
                    self.controller
                        .as_ref()
                        .map(|controller| controller.enable_actor)
                }),
            local_revision: revisions.local_revision,
            admission_revision: revisions.admission_revision,
            lease_authority_revision: revisions.lease_authority_revision,
            host_revision: revisions.host_revision,
            window_id: self.window.as_ref().map(|window| window.window_id.clone()),
            window_expires_at_ms: self.window.as_ref().map(|window| window.expires_at_ms),
            controller_id: self
                .controller
                .as_ref()
                .map(|_| self.policy.controller_id.clone()),
            session_expires_at_ms: self
                .controller
                .as_ref()
                .map(|controller| controller.session_expires_at_ms),
            idle_expires_at_ms: self
                .controller
                .as_ref()
                .map(|controller| controller.idle_expires_at_ms),
            last_accepted_command_receipt_id: self.last_accepted_command_receipt_id.clone(),
        }
    }

    /// Opens one short pairing window after explicit wearer authorization.
    ///
    /// This changes only source authority state; it never opens a socket.
    ///
    pub fn open_pairing_window(
        &mut self,
        request: &ManifoldLocalControlWindowRequest,
    ) -> ManifoldLocalControlWindowReceipt {
        let mut receipt = window_receipt(request, self);
        let rejection = if request.schema_id.as_str() != LOCAL_CONTROL_WINDOW_REQUEST_SCHEMA {
            Some(ManifoldLocalControlRejectionReason::SchemaMismatch)
        } else if let Err(rejection) = self.reject_replay_or_capacity(&request.request_id) {
            Some(rejection)
        } else if request.expected_local_revision != self.local_revision {
            Some(ManifoldLocalControlRejectionReason::StaleLocalRevision)
        } else if self.controller.is_some() {
            Some(ManifoldLocalControlRejectionReason::ControllerAlreadyActive)
        } else if request.enable_actor == ManifoldLocalControlEnableActor::DebugShell
            && !self.policy.allow_debug_shell_operator
        {
            Some(ManifoldLocalControlRejectionReason::AuthorityRejected)
        } else if request.opened_at_ms >= request.expires_at_ms
            || request.expires_at_ms - request.opened_at_ms > self.policy.max_window_ttl_ms
        {
            Some(ManifoldLocalControlRejectionReason::InvalidLifetime)
        } else {
            None
        };
        if let Some(rejection) = rejection {
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            receipt.resulting_revisions = self.revision_tuple();
            receipt.status = self.safe_status();
            return receipt;
        }
        self.remember_request(request.request_id.clone());
        self.window = Some(PairingWindow {
            window_id: request.window_id.clone(),
            expires_at_ms: request.expires_at_ms,
            access_mode: request.access_mode,
            enable_actor: request.enable_actor,
        });
        if self.advance_local_revision().is_err() {
            self.window = None;
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted);
        } else {
            receipt.opened = true;
        }
        receipt.resulting_revisions = self.revision_tuple();
        receipt.status = self.safe_status();
        receipt
    }

    /// Admits one exact controller and composes token, lease, and host state.
    ///
    /// Pairing entropy is supplied out of band and is never retained.
    pub fn admit_controller(
        &mut self,
        request: &ManifoldLocalControlAdmissionRequest,
        token_entropy: [u8; 32],
        clock: ManifoldClockSnapshot,
    ) -> ManifoldLocalControlAdmissionReceipt {
        let mut receipt = admission_receipt(&request.request_id);
        if let Some(rejection) = self.precheck_admission(request, &clock) {
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
        } else {
            receipt = self.apply_admission(request, token_entropy, clock, receipt);
        }
        receipt.resulting_revisions = self.revision_tuple();
        receipt
    }

    #[allow(clippy::too_many_lines)]
    fn apply_admission(
        &mut self,
        request: &ManifoldLocalControlAdmissionRequest,
        token_entropy: [u8; 32],
        clock: ManifoldClockSnapshot,
        mut receipt: ManifoldLocalControlAdmissionReceipt,
    ) -> ManifoldLocalControlAdmissionReceipt {
        self.remember_request(request.request_id.clone());
        let capabilities = command_capabilities(&self.policy);
        let issue_request = ManifoldAdmissionRequest {
            schema_id: schema_id(ADMISSION_REQUEST_SCHEMA),
            request_id: derived_id("request.local_control.admission.issue", &request.request_id),
            expected_authority_revision: request.expected_admission_revision,
            identity: self.policy.adapter_identity.clone(),
            requested_capabilities: capabilities,
            issued_at_ms: request.requested_at_ms,
            expires_at_ms: request.evidence.expires_at_ms,
            requested_token_ttl_ms: request.requested_session_ttl_ms,
        };
        let mut admission = self.admission.clone();
        let issue = admission.issue_token(&issue_request, token_entropy, request.requested_at_ms);
        receipt.admission = Some(issue.clone());
        let Some(token) = issue.token else {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        };

        let lease_request = ManifoldControlLeaseRequest {
            schema_id: schema_id("rusty.manifold.command.lease_request.v1"),
            request_id: derived_id("request.local_control.lease.issue", &request.request_id),
            holder_id: self.policy.controller_id.clone(),
            scope: self.policy.controller_lease_scope.clone(),
            expected_revision: request.expected_lease_authority_revision,
            requested_ttl_ms: request.requested_session_ttl_ms,
            required_capability: self.policy.controller_lease_capability_id.clone(),
            safety_class: SafetyClass::BoundedMutation,
        };
        let prior_lease_authority = self.lease_authority.clone();
        let Ok(review) = prior_lease_authority.review_lease_request(
            lease_request,
            clock,
            vec![request.evidence.evidence_id.clone()],
        ) else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };
        let Ok(application) = prior_lease_authority.apply_control_lease_authority_review(review)
        else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };
        receipt.lease_application = Some(application.clone());
        if application.outcome != ManifoldControlLeaseAuthorityApplicationOutcome::LeaseApplied {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }
        let Some(next_lease_authority) = application.applied_snapshot.clone() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };
        let Some(lease) = next_lease_authority
            .active_leases
            .iter()
            .find(|lease| {
                lease.holder_id == self.policy.controller_id
                    && lease.scope == self.policy.controller_lease_scope
            })
            .cloned()
        else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };

        let adoption_request = ManifoldRuntimeControlLeaseAdoptionRequest {
            schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
            adoption_id: derived_id("adoption.local_control.lease.issue", &request.request_id),
            expected_host_authority_revision: request.expected_host_revision,
            prior_authority_snapshot: prior_lease_authority,
            application: ManifoldRuntimeControlLeaseAuthorityApplication::Issue(
                application.clone(),
            ),
        };
        let mut runtime_host = self.runtime_host.clone();
        let adoption = runtime_host.apply_control_lease_adoption(&adoption_request);
        receipt.host_adoption = Some(adoption.clone());
        if !adoption.applied {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }

        let Some(local_revision) = self.local_revision.next() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted);
            return receipt;
        };
        let session_expires_at_ms = token.expires_at_ms.min(lease.expires_at_ms);
        self.admission = admission;
        self.lease_authority = next_lease_authority;
        self.runtime_host = runtime_host;
        self.local_revision = local_revision;
        self.controller = Some(ActiveController {
            token_id: token.token_id,
            lease,
            session_expires_at_ms,
            idle_expires_at_ms: request
                .requested_at_ms
                .saturating_add(self.policy.idle_timeout_ms)
                .min(session_expires_at_ms),
            access_mode: self
                .window
                .as_ref()
                .expect("admission precheck requires a window")
                .access_mode,
            enable_actor: self
                .window
                .as_ref()
                .expect("admission precheck requires a window")
                .enable_actor,
        });
        self.window = None;
        receipt.admitted = true;
        receipt
    }

    /// Reviews and accepts one command from the fixed registry.
    ///
    /// `command_accepted` proves only Manifold/Runtime Host acceptance. The app
    /// must emit a separate application-effect receipt from player callbacks.
    pub fn accept_command(
        &mut self,
        request: &ManifoldLocalControlCommandRequest,
        now_ms: u64,
    ) -> ManifoldLocalControlCommandReceipt {
        let mut receipt = self.accept_command_inner(request, now_ms);
        receipt.resulting_revisions = self.revision_tuple();
        receipt
    }

    fn accept_command_inner(
        &mut self,
        request: &ManifoldLocalControlCommandRequest,
        now_ms: u64,
    ) -> ManifoldLocalControlCommandReceipt {
        let mut receipt = command_receipt(&request.request_id, &request.command_id);
        let base_rejection = if request.schema_id.as_str() != LOCAL_CONTROL_COMMAND_REQUEST_SCHEMA {
            Some(ManifoldLocalControlRejectionReason::SchemaMismatch)
        } else if let Err(rejection) = self.reject_replay_or_capacity(&request.request_id) {
            Some(rejection)
        } else if self.local_revision.next().is_none() {
            Some(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted)
        } else {
            self.common_revision_rejection(
                request.expected_local_revision,
                request.expected_admission_revision,
                None,
                request.expected_host_revision,
            )
        };
        if let Some(rejection) = base_rejection {
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        let Some(descriptor) = self
            .policy
            .commands
            .iter()
            .find(|descriptor| descriptor.command_id == request.command_id)
            .cloned()
        else {
            let rejection = ManifoldLocalControlRejectionReason::UnknownCommand;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        };
        if let Some(rejection) = self.precheck_command(request, &descriptor, now_ms) {
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        self.remember_request(request.request_id.clone());
        self.record_rate_attempt(now_ms);

        let Some(controller) = self.controller.as_ref() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };
        receipt.controller_lease_id = Some(controller.lease.lease_id.clone());
        let use_request = ManifoldAdmissionUseRequest {
            schema_id: schema_id(ADMISSION_USE_REQUEST_SCHEMA),
            request_id: request.request_id.clone(),
            expected_authority_revision: request.expected_admission_revision,
            token_id: request.token_id.clone(),
            identity: self.policy.adapter_identity.clone(),
            capability_id: descriptor.capability_id,
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
        };
        let use_receipt = self.admission.authorize_use(&use_request, now_ms);
        receipt.admission_use = Some(use_receipt.clone());
        if !use_receipt.applied {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }
        let Some(local_revision) = self.local_revision.next() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted);
            return receipt;
        };
        // Admission use is now committed. Advance the enclosing composite
        // revision even if the following Runtime Host attempt rejects.
        self.local_revision = local_revision;

        let runtime_request = ManifoldRuntimeCommandRequest {
            schema_id: schema_id(HOST_COMMAND_REQUEST_SCHEMA),
            request_id: request.request_id.clone(),
            expected_authority_revision: request.expected_host_revision,
            requester_id: self.policy.controller_id.clone(),
            command_id: request.command_id.clone(),
            lease_id: descriptor
                .required_lease_scope
                .as_ref()
                .map(|_| controller.lease.lease_id.clone()),
            params_digest: request.params_digest.clone(),
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
        };
        let dispatch = self.runtime_host.review_command(&runtime_request, now_ms);
        let application = self
            .runtime_host
            .apply_dispatch(&runtime_request, &dispatch, now_ms);
        receipt.dispatch = Some(dispatch);
        receipt.application = Some(application.clone());
        if !application.applied {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }

        if let Some(controller) = &mut self.controller {
            controller.idle_expires_at_ms = now_ms
                .saturating_add(self.policy.idle_timeout_ms)
                .min(controller.session_expires_at_ms);
        }
        receipt.command_accepted = true;
        self.last_accepted_command_receipt_id = Some(receipt.receipt_id.clone());
        receipt
    }

    /// Terminally revokes the active controller under retained authority.
    pub fn revoke_controller(
        &mut self,
        request: &ManifoldLocalControlRevocationRequest,
        clock: ManifoldClockSnapshot,
    ) -> ManifoldLocalControlRevocationReceipt {
        let mut receipt = revocation_receipt(&request.request_id);
        if let Some(rejection) = self.precheck_revocation(request, &clock) {
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
        } else {
            receipt = self.apply_revocation(request, clock, receipt);
        }
        receipt.resulting_revisions = self.revision_tuple();
        receipt
    }

    fn apply_revocation(
        &mut self,
        request: &ManifoldLocalControlRevocationRequest,
        clock: ManifoldClockSnapshot,
        mut receipt: ManifoldLocalControlRevocationReceipt,
    ) -> ManifoldLocalControlRevocationReceipt {
        self.remember_request(request.request_id.clone());
        let controller = self.controller.as_ref().expect("prechecked controller");
        let mut admission = self.admission.clone();
        let admission_request = ManifoldAdmissionAdministrativeRevocationRequest {
            schema_id: schema_id(ADMISSION_ADMINISTRATIVE_REVOCATION_REQUEST_SCHEMA),
            request_id: derived_id(
                "request.local_control.admission.revoke",
                &request.request_id,
            ),
            authority_id: self.admission.snapshot().authority_id.clone(),
            expected_authority_revision: request.expected_admission_revision,
            token_id: controller.token_id.clone(),
            reason: request.reason.clone(),
            requested_at_ms: request.requested_at_ms,
        };
        let admission_revocation = admission.administratively_revoke_token(&admission_request);
        receipt.admission_revocation = Some(admission_revocation.clone());
        if !admission_revocation.applied {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }

        let prior_lease_authority = self.lease_authority.clone();
        let lease_request = ManifoldControlLeaseRevocationRequest {
            schema_id: schema_id("rusty.manifold.command.lease_revocation_request.v1"),
            request_id: derived_id("request.local_control.lease.revoke", &request.request_id),
            authority_id: prior_lease_authority.authority_id.clone(),
            lease_id: controller.lease.lease_id.clone(),
            expected_authority_revision: request.expected_lease_authority_revision,
            scope: self.policy.controller_lease_scope.clone(),
            revocation_reason: request.reason.clone(),
            requested_at_ms: request.requested_at_ms,
        };
        let Ok(review) = prior_lease_authority.review_control_lease_revocation(
            lease_request,
            clock,
            vec![request.evidence_id.clone()],
        ) else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };
        let Ok(application) =
            prior_lease_authority.apply_control_lease_revocation_authority_review(review)
        else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };
        receipt.lease_revocation = Some(application.clone());
        if application.outcome
            != ManifoldControlLeaseRevocationAuthorityApplicationOutcome::LeaseRevocationApplied
        {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }
        let Some(next_lease_authority) = application.applied_snapshot.clone() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
            return receipt;
        };

        let adoption_request = ManifoldRuntimeControlLeaseAdoptionRequest {
            schema_id: schema_id(HOST_CONTROL_LEASE_ADOPTION_REQUEST_SCHEMA),
            adoption_id: derived_id("adoption.local_control.lease.revoke", &request.request_id),
            expected_host_authority_revision: request.expected_host_revision,
            prior_authority_snapshot: prior_lease_authority,
            application: ManifoldRuntimeControlLeaseAuthorityApplication::Revocation(Box::new(
                application,
            )),
        };
        let mut runtime_host = self.runtime_host.clone();
        let adoption = runtime_host.apply_control_lease_adoption(&adoption_request);
        receipt.host_adoption = Some(adoption.clone());
        if !adoption.applied {
            receipt.rejection_reason = Some(ManifoldLocalControlRejectionReason::AuthorityRejected);
            return receipt;
        }
        let Some(local_revision) = self.local_revision.next() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted);
            return receipt;
        };
        self.admission = admission;
        self.lease_authority = next_lease_authority;
        self.runtime_host = runtime_host;
        self.local_revision = local_revision;
        self.controller = None;
        self.window = None;
        self.last_accepted_command_receipt_id = None;
        receipt.revoked = true;
        receipt
    }

    /// Explicitly enforces session or idle expiry through authority revocation.
    pub fn expire_controller(
        &mut self,
        request: &ManifoldLocalControlExpiryRequest,
        clock: ManifoldClockSnapshot,
    ) -> ManifoldLocalControlExpiryReceipt {
        let mut receipt = self.expire_controller_inner(request, clock);
        receipt.resulting_revisions = self.revision_tuple();
        receipt
    }

    fn expire_controller_inner(
        &mut self,
        request: &ManifoldLocalControlExpiryRequest,
        clock: ManifoldClockSnapshot,
    ) -> ManifoldLocalControlExpiryReceipt {
        let mut receipt = expiry_receipt(&request.request_id);
        if request.schema_id.as_str() != LOCAL_CONTROL_EXPIRY_REQUEST_SCHEMA {
            let rejection = ManifoldLocalControlRejectionReason::SchemaMismatch;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        if let Err(rejection) = self.reject_replay_or_capacity(&request.request_id) {
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        if request.expected_local_revision != self.local_revision {
            let rejection = ManifoldLocalControlRejectionReason::StaleLocalRevision;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        if request.expected_admission_revision != self.admission.snapshot().authority_revision {
            let rejection = ManifoldLocalControlRejectionReason::StaleAdmissionRevision;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        if request.expected_lease_authority_revision != self.lease_authority.authority_revision {
            let rejection = ManifoldLocalControlRejectionReason::StaleLeaseAuthorityRevision;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        if request.expected_host_revision != self.runtime_host.snapshot().authority_revision {
            let rejection = ManifoldLocalControlRejectionReason::StaleHostRevision;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        let Some(controller) = self.controller.as_ref() else {
            let rejection = ManifoldLocalControlRejectionReason::NoActiveController;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        };
        if request.requested_at_ms < controller.session_expires_at_ms
            && request.requested_at_ms < controller.idle_expires_at_ms
        {
            let rejection = ManifoldLocalControlRejectionReason::NotExpired;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        let reason = if request.requested_at_ms >= controller.session_expires_at_ms {
            dotted_id("reason.local_control.session_expired")
        } else {
            dotted_id("reason.local_control.idle_expired")
        };
        let revocation_request = ManifoldLocalControlRevocationRequest {
            schema_id: schema_id(LOCAL_CONTROL_REVOCATION_REQUEST_SCHEMA),
            request_id: request.request_id.clone(),
            expected_local_revision: request.expected_local_revision,
            expected_admission_revision: request.expected_admission_revision,
            expected_lease_authority_revision: request.expected_lease_authority_revision,
            expected_host_revision: request.expected_host_revision,
            reason,
            requested_at_ms: request.requested_at_ms,
            evidence_id: request.evidence_id.clone(),
        };
        let revocation = self.revoke_controller(&revocation_request, clock);
        receipt.expired = revocation.revoked;
        receipt
            .rejection_reason
            .clone_from(&revocation.rejection_reason);
        receipt.revocation = Some(revocation);
        receipt
    }

    /// Returns an open window or active controller to disabled state.
    ///
    /// An active controller routes through the complete terminal revocation
    /// chain. An unadmitted window closes locally, allowing listener-start
    /// failure or wearer cancellation to be represented honestly.
    pub fn disable(
        &mut self,
        request: &ManifoldLocalControlDisableRequest,
        clock: ManifoldClockSnapshot,
    ) -> ManifoldLocalControlDisableReceipt {
        let mut receipt = self.disable_inner(request, clock);
        receipt.resulting_revisions = self.revision_tuple();
        receipt
    }

    fn disable_inner(
        &mut self,
        request: &ManifoldLocalControlDisableRequest,
        clock: ManifoldClockSnapshot,
    ) -> ManifoldLocalControlDisableReceipt {
        let prior_state = self.safe_status().state;
        let mut receipt = disable_receipt(&request.request_id, prior_state);
        let rejection = if request.schema_id.as_str() != LOCAL_CONTROL_DISABLE_REQUEST_SCHEMA {
            Some(ManifoldLocalControlRejectionReason::SchemaMismatch)
        } else if let Err(rejection) = self.reject_replay_or_capacity(&request.request_id) {
            Some(rejection)
        } else {
            self.common_revision_rejection(
                request.expected_local_revision,
                request.expected_admission_revision,
                Some(request.expected_lease_authority_revision),
                request.expected_host_revision,
            )
        };
        if let Some(rejection) = rejection {
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        if self.controller.is_some() {
            let revocation = self.revoke_controller(
                &ManifoldLocalControlRevocationRequest {
                    schema_id: schema_id(LOCAL_CONTROL_REVOCATION_REQUEST_SCHEMA),
                    request_id: request.request_id.clone(),
                    expected_local_revision: request.expected_local_revision,
                    expected_admission_revision: request.expected_admission_revision,
                    expected_lease_authority_revision: request.expected_lease_authority_revision,
                    expected_host_revision: request.expected_host_revision,
                    reason: request.reason.clone(),
                    requested_at_ms: request.requested_at_ms,
                    evidence_id: request.evidence_id.clone(),
                },
                clock,
            );
            receipt.disabled = revocation.revoked;
            receipt
                .rejection_reason
                .clone_from(&revocation.rejection_reason);
            receipt.revocation = Some(revocation);
            return receipt;
        }
        if self.window.is_none() {
            let rejection = ManifoldLocalControlRejectionReason::Disabled;
            self.remember_rejected_request(&request.request_id, &rejection);
            receipt.rejection_reason = Some(rejection);
            return receipt;
        }
        let Some(local_revision) = self.local_revision.next() else {
            receipt.rejection_reason =
                Some(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted);
            return receipt;
        };
        self.remember_request(request.request_id.clone());
        self.window = None;
        self.local_revision = local_revision;
        receipt.disabled = true;
        receipt
    }

    fn precheck_admission(
        &self,
        request: &ManifoldLocalControlAdmissionRequest,
        clock: &ManifoldClockSnapshot,
    ) -> Option<ManifoldLocalControlRejectionReason> {
        if request.schema_id.as_str() != LOCAL_CONTROL_ADMISSION_REQUEST_SCHEMA {
            return Some(ManifoldLocalControlRejectionReason::SchemaMismatch);
        }
        if let Err(rejection) = self.reject_replay_or_capacity(&request.request_id) {
            return Some(rejection);
        }
        if let Some(rejection) = self.common_revision_rejection(
            request.expected_local_revision,
            request.expected_admission_revision,
            Some(request.expected_lease_authority_revision),
            request.expected_host_revision,
        ) {
            return Some(rejection);
        }
        if self.controller.is_some() {
            return Some(ManifoldLocalControlRejectionReason::ControllerAlreadyActive);
        }
        let Some(window) = &self.window else {
            return Some(ManifoldLocalControlRejectionReason::Disabled);
        };
        if request.requested_at_ms >= window.expires_at_ms {
            return Some(ManifoldLocalControlRejectionReason::Expired);
        }
        let evidence = &request.evidence;
        let access_evidence_valid = match window.access_mode {
            ManifoldLocalControlAccessMode::Paired => {
                matches!(
                    evidence.presentation,
                    ManifoldLocalControlPairingPresentation::ManualEntry
                        | ManifoldLocalControlPairingPresentation::QrConvenience
                ) && evidence.pairing_code_verified
            }
            ManifoldLocalControlAccessMode::OpenLanInsecure => {
                evidence.presentation == ManifoldLocalControlPairingPresentation::OpenLanInsecure
                    && !evidence.pairing_code_verified
            }
        };
        if evidence.schema_id.as_str() != LOCAL_CONTROL_CONTROLLER_EVIDENCE_SCHEMA
            || evidence.adapter_id != self.policy.trusted_adapter_id
            || evidence.window_id != window.window_id
            || evidence.controller_id != self.policy.controller_id
            || !access_evidence_valid
            || evidence.observed_at_ms > request.requested_at_ms
            || evidence.expires_at_ms <= request.requested_at_ms
            || evidence.expires_at_ms > window.expires_at_ms
        {
            return Some(ManifoldLocalControlRejectionReason::PairingEvidenceInvalid);
        }
        if request.requested_session_ttl_ms == 0
            || request.requested_session_ttl_ms > self.policy.max_session_ttl_ms
        {
            return Some(ManifoldLocalControlRejectionReason::InvalidLifetime);
        }
        if !clock_matches(&self.lease_authority.clock_snapshot, clock) {
            return Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
        }
        None
    }

    fn precheck_command(
        &mut self,
        request: &ManifoldLocalControlCommandRequest,
        descriptor: &ManifoldLocalControlCommandDescriptor,
        now_ms: u64,
    ) -> Option<ManifoldLocalControlRejectionReason> {
        let Some(controller) = &self.controller else {
            return Some(ManifoldLocalControlRejectionReason::NoActiveController);
        };
        if request.token_id != controller.token_id {
            return Some(ManifoldLocalControlRejectionReason::ControllerMismatch);
        }
        if now_ms >= controller.session_expires_at_ms || now_ms >= controller.idle_expires_at_ms {
            return Some(ManifoldLocalControlRejectionReason::Expired);
        }
        if request.issued_at_ms > now_ms || request.expires_at_ms <= now_ms {
            return Some(ManifoldLocalControlRejectionReason::Expired);
        }
        if descriptor.params_type_id.as_ref()
            != request
                .params_digest
                .as_ref()
                .map(|digest| &digest.params_type_id)
        {
            return Some(ManifoldLocalControlRejectionReason::InvalidTypedParams);
        }
        self.prune_rate_attempts(now_ms);
        if self.command_attempt_times_ms.len() >= usize::from(self.policy.max_commands_per_window) {
            return Some(ManifoldLocalControlRejectionReason::RateLimited);
        }
        None
    }

    fn precheck_revocation(
        &self,
        request: &ManifoldLocalControlRevocationRequest,
        clock: &ManifoldClockSnapshot,
    ) -> Option<ManifoldLocalControlRejectionReason> {
        if request.schema_id.as_str() != LOCAL_CONTROL_REVOCATION_REQUEST_SCHEMA {
            return Some(ManifoldLocalControlRejectionReason::SchemaMismatch);
        }
        if let Err(rejection) = self.reject_replay_or_capacity(&request.request_id) {
            return Some(rejection);
        }
        if let Some(rejection) = self.common_revision_rejection(
            request.expected_local_revision,
            request.expected_admission_revision,
            Some(request.expected_lease_authority_revision),
            request.expected_host_revision,
        ) {
            return Some(rejection);
        }
        if self.controller.is_none() {
            return Some(ManifoldLocalControlRejectionReason::NoActiveController);
        }
        if !clock_matches(&self.lease_authority.clock_snapshot, clock) {
            return Some(ManifoldLocalControlRejectionReason::AuthorityInvariant);
        }
        None
    }

    fn common_revision_rejection(
        &self,
        local: Revision,
        admission: Revision,
        lease: Option<Revision>,
        host: Revision,
    ) -> Option<ManifoldLocalControlRejectionReason> {
        if local != self.local_revision {
            Some(ManifoldLocalControlRejectionReason::StaleLocalRevision)
        } else if admission != self.admission.snapshot().authority_revision {
            Some(ManifoldLocalControlRejectionReason::StaleAdmissionRevision)
        } else if lease.is_some_and(|revision| revision != self.lease_authority.authority_revision)
        {
            Some(ManifoldLocalControlRejectionReason::StaleLeaseAuthorityRevision)
        } else if host != self.runtime_host.snapshot().authority_revision {
            Some(ManifoldLocalControlRejectionReason::StaleHostRevision)
        } else {
            None
        }
    }

    fn reject_replay_or_capacity(
        &self,
        request_id: &DottedId,
    ) -> Result<(), ManifoldLocalControlRejectionReason> {
        if self.reviewed_request_ids.contains(request_id) {
            Err(ManifoldLocalControlRejectionReason::ReplayedRequest)
        } else if self.reviewed_request_ids.len() >= MAX_REPLAY_IDS {
            Err(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted)
        } else {
            Ok(())
        }
    }

    fn remember_request(&mut self, request_id: DottedId) {
        self.reviewed_request_ids.push(request_id);
        self.reviewed_request_ids.sort();
    }

    fn remember_rejected_request(
        &mut self,
        request_id: &DottedId,
        rejection: &ManifoldLocalControlRejectionReason,
    ) {
        if !matches!(
            rejection,
            ManifoldLocalControlRejectionReason::ReplayedRequest
                | ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted
        ) && !self.reviewed_request_ids.contains(request_id)
            && self.reviewed_request_ids.len() < MAX_REPLAY_IDS
        {
            self.remember_request(request_id.clone());
        }
    }

    fn prune_rate_attempts(&mut self, now_ms: u64) {
        let earliest = now_ms.saturating_sub(self.policy.rate_window_ms);
        self.command_attempt_times_ms
            .retain(|attempt| *attempt > earliest);
    }

    fn record_rate_attempt(&mut self, now_ms: u64) {
        self.command_attempt_times_ms.push(now_ms);
        self.command_attempt_times_ms.sort_unstable();
    }

    fn advance_local_revision(&mut self) -> Result<(), ManifoldLocalControlRejectionReason> {
        self.local_revision = self
            .local_revision
            .next()
            .ok_or(ManifoldLocalControlRejectionReason::AuthorityCapacityExhausted)?;
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
fn validate_policy(
    policy: &ManifoldLocalControlPolicy,
    admission: &ManifoldAdmissionAuthority,
    lease_authority: &ManifoldAuthoritySnapshot,
    runtime_host: &ManifoldRuntimeHost,
) -> Result<(), ManifoldLocalControlError> {
    if policy.schema_id.as_str() != LOCAL_CONTROL_POLICY_SCHEMA {
        return Err(ManifoldLocalControlError::new("policy_schema"));
    }
    if policy.authority_id != lease_authority.authority_id {
        return Err(ManifoldLocalControlError::new("authority_id"));
    }
    if policy.trusted_adapter_id != policy.adapter_identity.client_id
        || policy.controller_id == policy.adapter_identity.client_id
    {
        return Err(ManifoldLocalControlError::new("adapter_identity"));
    }
    lease_authority
        .validate_authority_links()
        .map_err(|_| ManifoldLocalControlError::new("lease_authority"))?;
    if runtime_host.snapshot().host_id != lease_authority.host_manifest.host_id {
        return Err(ManifoldLocalControlError::new("host_id"));
    }
    if policy.commands.is_empty() || policy.commands.len() > MAX_COMMANDS {
        return Err(ManifoldLocalControlError::new("commands"));
    }
    if policy.max_window_ttl_ms == 0
        || policy.max_window_ttl_ms > MAX_WINDOW_TTL_MS
        || policy.max_session_ttl_ms == 0
        || policy.max_session_ttl_ms > MAX_SESSION_TTL_MS
        || policy.idle_timeout_ms == 0
        || policy.idle_timeout_ms > policy.max_session_ttl_ms
        || policy.idle_timeout_ms > MAX_IDLE_TIMEOUT_MS
        || policy.rate_window_ms == 0
        || policy.rate_window_ms > MAX_RATE_WINDOW_MS
        || policy.max_commands_per_window == 0
        || policy.max_commands_per_window > MAX_RATE_LIMIT
    {
        return Err(ManifoldLocalControlError::new("policy_bounds"));
    }
    let command_ids = policy
        .commands
        .iter()
        .map(|command| command.command_id.clone())
        .collect::<Vec<_>>();
    if command_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ManifoldLocalControlError::new("command_order"));
    }
    let runtime_commands = runtime_host
        .snapshot()
        .commands
        .iter()
        .map(|command| {
            (
                command.command_id.clone(),
                command.required_lease_scope.clone(),
            )
        })
        .collect::<Vec<_>>();
    let policy_commands = policy
        .commands
        .iter()
        .map(|command| {
            (
                command.command_id.clone(),
                command.required_lease_scope.clone(),
            )
        })
        .collect::<Vec<_>>();
    if runtime_commands != policy_commands {
        return Err(ManifoldLocalControlError::new("runtime_registry"));
    }
    if policy.commands.iter().any(|command| {
        !lease_authority
            .command_descriptors
            .iter()
            .any(|descriptor| {
                descriptor.command_id == command.command_id
                    && descriptor.required_capability == command.capability_id
                    && descriptor.required_lease_scope == command.required_lease_scope
            })
    }) {
        return Err(ManifoldLocalControlError::new("lease_registry"));
    }
    if policy.commands.iter().any(|command| {
        command
            .required_lease_scope
            .as_ref()
            .is_some_and(|scope| scope != &policy.controller_lease_scope)
    }) {
        return Err(ManifoldLocalControlError::new("lease_scope"));
    }
    let grant = admission
        .snapshot()
        .grants
        .iter()
        .find(|grant| grant.identity == policy.adapter_identity)
        .ok_or_else(|| ManifoldLocalControlError::new("admission_identity"))?;
    let required_capabilities = command_capabilities(policy);
    if required_capabilities
        .iter()
        .any(|capability| !grant.capabilities.contains(capability))
        || !lease_authority
            .host_manifest
            .capabilities
            .contains(&policy.controller_lease_capability_id)
    {
        return Err(ManifoldLocalControlError::new("capabilities"));
    }
    Ok(())
}

fn command_capabilities(policy: &ManifoldLocalControlPolicy) -> Vec<DottedId> {
    let mut capabilities = policy
        .commands
        .iter()
        .map(|command| command.capability_id.clone())
        .collect::<BTreeSet<_>>();
    capabilities.insert(policy.controller_lease_capability_id.clone());
    capabilities.into_iter().collect()
}

fn clock_matches(prior: &ManifoldClockSnapshot, next: &ManifoldClockSnapshot) -> bool {
    prior.clock_domain == next.clock_domain
        && prior.clock_epoch_id == next.clock_epoch_id
        && next.sequence >= prior.sequence
        && next.monotonic_elapsed_ns >= prior.monotonic_elapsed_ns
        && next.wall_clock_adjustment_count >= prior.wall_clock_adjustment_count
        && (next.sequence != prior.sequence || next == prior)
}

fn admission_receipt(request_id: &DottedId) -> ManifoldLocalControlAdmissionReceipt {
    ManifoldLocalControlAdmissionReceipt {
        schema_id: schema_id(LOCAL_CONTROL_ADMISSION_RECEIPT_SCHEMA),
        receipt_id: derived_id("receipt.local_control.admission", request_id),
        request_id: request_id.clone(),
        admitted: false,
        resulting_revisions: initial_revision_tuple(),
        admission: None,
        lease_application: None,
        host_adoption: None,
        rejection_reason: None,
    }
}

fn command_receipt(
    request_id: &DottedId,
    command_id: &DottedId,
) -> ManifoldLocalControlCommandReceipt {
    ManifoldLocalControlCommandReceipt {
        schema_id: schema_id(LOCAL_CONTROL_COMMAND_RECEIPT_SCHEMA),
        receipt_id: derived_id("receipt.local_control.command", request_id),
        request_id: request_id.clone(),
        command_id: command_id.clone(),
        command_accepted: false,
        controller_lease_id: None,
        resulting_revisions: initial_revision_tuple(),
        proves_application_effect: false,
        admission_use: None,
        dispatch: None,
        application: None,
        rejection_reason: None,
    }
}

fn revocation_receipt(request_id: &DottedId) -> ManifoldLocalControlRevocationReceipt {
    ManifoldLocalControlRevocationReceipt {
        schema_id: schema_id(LOCAL_CONTROL_REVOCATION_RECEIPT_SCHEMA),
        receipt_id: derived_id("receipt.local_control.revocation", request_id),
        request_id: request_id.clone(),
        revoked: false,
        resulting_revisions: initial_revision_tuple(),
        admission_revocation: None,
        lease_revocation: None,
        host_adoption: None,
        rejection_reason: None,
    }
}

fn expiry_receipt(request_id: &DottedId) -> ManifoldLocalControlExpiryReceipt {
    ManifoldLocalControlExpiryReceipt {
        schema_id: schema_id(LOCAL_CONTROL_EXPIRY_RECEIPT_SCHEMA),
        receipt_id: derived_id("receipt.local_control.expiry", request_id),
        request_id: request_id.clone(),
        expired: false,
        resulting_revisions: initial_revision_tuple(),
        revocation: None,
        rejection_reason: None,
    }
}

fn disable_receipt(
    request_id: &DottedId,
    prior_state: ManifoldLocalControlState,
) -> ManifoldLocalControlDisableReceipt {
    ManifoldLocalControlDisableReceipt {
        schema_id: schema_id(LOCAL_CONTROL_DISABLE_RECEIPT_SCHEMA),
        receipt_id: derived_id("receipt.local_control.disable", request_id),
        request_id: request_id.clone(),
        prior_state,
        disabled: false,
        resulting_revisions: initial_revision_tuple(),
        revocation: None,
        rejection_reason: None,
    }
}

fn window_receipt(
    request: &ManifoldLocalControlWindowRequest,
    authority: &ManifoldLocalControlAuthority,
) -> ManifoldLocalControlWindowReceipt {
    ManifoldLocalControlWindowReceipt {
        schema_id: schema_id(LOCAL_CONTROL_WINDOW_RECEIPT_SCHEMA),
        receipt_id: derived_id("receipt.local_control.window", &request.request_id),
        request_id: request.request_id.clone(),
        window_id: request.window_id.clone(),
        access_mode: request.access_mode,
        enable_actor: request.enable_actor,
        opened: false,
        resulting_revisions: authority.revision_tuple(),
        status: authority.safe_status(),
        rejection_reason: None,
    }
}

fn initial_revision_tuple() -> ManifoldLocalControlRevisionTuple {
    ManifoldLocalControlRevisionTuple {
        local_revision: Revision::INITIAL,
        admission_revision: Revision::INITIAL,
        lease_authority_revision: Revision::INITIAL,
        host_revision: Revision::INITIAL,
    }
}

fn derived_id(prefix: &str, source: &DottedId) -> DottedId {
    dotted_id(&format!("{prefix}.{}", source.as_str()))
}

fn dotted_id(value: &str) -> DottedId {
    DottedId::new(value).expect("static prefix and validated source form a dotted id")
}

fn schema_id(value: &str) -> SchemaId {
    SchemaId::new(value).expect("static schema id")
}

#[cfg(test)]
mod tests;
