//! Optional pure-Rust ZeroMQ adapter helpers for Manifold bridge routes.
//!
//! The crate consumes `ManifoldBridgeRouteDescriptor` values that declare a
//! generic ZeroMQ profile. Default builds are model-only and socket-free. The
//! `runtime` feature enables a small PUB/SUB receiver using the pure Rust
//! `zeromq` crate without linking native `libzmq`.

use rusty_manifold_model::{
    DottedId, ManifoldBridgePayloadClass, ManifoldBridgeRouteDescriptor,
    ManifoldBridgeRouteValidationError, ManifoldBridgeTransportFamily, ManifoldQueueDropPolicy,
    ManifoldZeroMqEndpointOpenMode, ManifoldZeroMqPayloadEncoding, ManifoldZeroMqSocketPattern,
};
use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};

#[cfg(feature = "runtime")]
use std::{
    io,
    sync::mpsc::{self, Sender, TryRecvError},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "runtime")]
use zeromq::{Socket, SocketRecv, SubSocket, ZmqMessage};

/// Crate version exposed for smoke checks.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Versioned schema id for received ZeroMQ messages.
pub const MANIFOLD_ZMQ_RECEIVED_MESSAGE_SCHEMA: &str = "rusty.manifold.zmq.received_message.v1";

/// Versioned schema id for receiver snapshots.
pub const MANIFOLD_ZMQ_RECEIVER_SNAPSHOT_SCHEMA: &str = "rusty.manifold.zmq.receiver_snapshot.v1";

const DEFAULT_RECEIVE_TIMEOUT_MS: u64 = 25;

/// Whether a runtime adapter binds or connects the configured endpoint.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldZmqOpenMode {
    /// Bind the endpoint locally.
    Bind,
    /// Connect to an endpoint bound by another participant.
    Connect,
}

/// Runtime state for a bounded ZeroMQ receiver.
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifoldZmqReceiverStatus {
    /// Receiver thread has started but is not connected.
    Starting,
    /// Socket setup and subscription succeeded.
    Connected,
    /// Receiver hit an unrecoverable adapter fault.
    Fault,
    /// Receiver shut down cleanly.
    Stopped,
}

/// Errors returned by route conversion and runtime setup helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifoldZmqAdapterError {
    /// The Manifold route descriptor failed its own validation.
    InvalidRoute(String),
    /// The descriptor does not select ZeroMQ.
    UnsupportedTransport(ManifoldBridgeTransportFamily),
    /// The descriptor is missing its ZeroMQ profile.
    MissingProfile,
    /// Only PUB/SUB is implemented by this first adapter.
    UnsupportedPattern(ManifoldZeroMqSocketPattern),
    /// Runtime use requires a concrete bind or connect mode.
    AmbiguousOpenMode,
    /// A received payload exceeded the route's configured maximum.
    MessageTooLarge {
        /// Actual message length.
        actual: usize,
        /// Configured maximum.
        max: usize,
    },
}

impl fmt::Display for ManifoldZmqAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoute(error) => {
                write!(formatter, "invalid Manifold ZeroMQ route: {error}")
            }
            Self::UnsupportedTransport(transport) => {
                write!(
                    formatter,
                    "unsupported transport family for ZeroMQ adapter: {transport:?}"
                )
            }
            Self::MissingProfile => formatter.write_str("ZeroMQ route profile is missing"),
            Self::UnsupportedPattern(pattern) => {
                write!(formatter, "unsupported ZeroMQ socket pattern: {pattern:?}")
            }
            Self::AmbiguousOpenMode => {
                formatter.write_str("ZeroMQ runtime adapter requires bind or connect mode")
            }
            Self::MessageTooLarge { actual, max } => {
                write!(
                    formatter,
                    "ZeroMQ message is too large: {actual} bytes > {max} bytes"
                )
            }
        }
    }
}

impl Error for ManifoldZmqAdapterError {}

impl From<ManifoldBridgeRouteValidationError> for ManifoldZmqAdapterError {
    fn from(source: ManifoldBridgeRouteValidationError) -> Self {
        Self::InvalidRoute(source.to_string())
    }
}

/// Receiver configuration derived from a Manifold bridge route.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldZmqPubSubReceiverConfig {
    /// Manifold bridge-route id.
    pub route_id: DottedId,
    /// Endpoint URL such as `tcp://127.0.0.1:5570`.
    pub endpoint: String,
    /// PUB/SUB topic prefix.
    pub topic_prefix: String,
    /// Runtime open mode.
    pub open_mode: ManifoldZmqOpenMode,
    /// Bounded queue capacity.
    pub queue_capacity: usize,
    /// Receive poll timeout.
    pub receive_timeout_ms: u64,
    /// Declared payload encoding.
    pub payload_encoding: ManifoldZeroMqPayloadEncoding,
    /// Declared Manifold payload class.
    pub payload_class: ManifoldBridgePayloadClass,
    /// Maximum allowed message size.
    pub max_message_bytes: usize,
    /// Queue pressure policy.
    pub queue_policy: ManifoldQueueDropPolicy,
}

impl ManifoldZmqPubSubReceiverConfig {
    /// Builds a receiver config from a generic Manifold ZeroMQ route descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldZmqAdapterError`] when the descriptor is not a concrete
    /// ZeroMQ PUB/SUB route suitable for this runtime helper.
    pub fn try_from_route(
        route: &ManifoldBridgeRouteDescriptor,
    ) -> Result<Self, ManifoldZmqAdapterError> {
        route.validate_shape()?;
        if route.transport_family != ManifoldBridgeTransportFamily::ZeroMq {
            return Err(ManifoldZmqAdapterError::UnsupportedTransport(
                route.transport_family,
            ));
        }
        let profile = route
            .zeromq
            .as_ref()
            .ok_or(ManifoldZmqAdapterError::MissingProfile)?;
        if profile.socket_pattern != ManifoldZeroMqSocketPattern::PubSub {
            return Err(ManifoldZmqAdapterError::UnsupportedPattern(
                profile.socket_pattern,
            ));
        }
        let open_mode = match profile.endpoint_open_mode {
            ManifoldZeroMqEndpointOpenMode::Bind => ManifoldZmqOpenMode::Bind,
            ManifoldZeroMqEndpointOpenMode::Connect => ManifoldZmqOpenMode::Connect,
            ManifoldZeroMqEndpointOpenMode::Either => {
                return Err(ManifoldZmqAdapterError::AmbiguousOpenMode);
            }
        };

        Ok(Self {
            route_id: route.route_id.clone(),
            endpoint: profile.endpoint_url.clone(),
            topic_prefix: profile.topic_prefix.clone(),
            open_mode,
            queue_capacity: usize::try_from(profile.high_water_mark)
                .unwrap_or(usize::MAX)
                .max(1),
            receive_timeout_ms: DEFAULT_RECEIVE_TIMEOUT_MS,
            payload_encoding: profile.payload_encoding,
            payload_class: route.payload_class,
            max_message_bytes: usize::try_from(profile.max_message_bytes)
                .unwrap_or(usize::MAX)
                .max(1),
            queue_policy: profile.queue_policy,
        })
    }

    /// Sets the runtime receive timeout.
    #[must_use]
    pub const fn with_receive_timeout_ms(mut self, receive_timeout_ms: u64) -> Self {
        self.receive_timeout_ms = receive_timeout_ms;
        self
    }
}

/// A received ZeroMQ payload normalized for Manifold ingestion.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldZmqReceivedMessage {
    /// Message schema id.
    pub schema: String,
    /// Manifold bridge-route id.
    pub route_id: DottedId,
    /// Endpoint URL.
    pub endpoint: String,
    /// Topic prefix used by the receiver.
    pub topic_prefix: String,
    /// Monotonic sequence assigned by the adapter.
    pub sequence_number: u64,
    /// Host receive timestamp.
    pub received_time_unix_ns: u128,
    /// Payload encoding declared by the route.
    pub payload_encoding: ManifoldZeroMqPayloadEncoding,
    /// Payload class declared by the route.
    pub payload_class: ManifoldBridgePayloadClass,
    /// Raw ZeroMQ message bytes.
    pub raw_bytes: Vec<u8>,
    /// UTF-8 payload text when decodable.
    pub utf8_text: Option<String>,
    /// Decode or topic-prefix problem, if any.
    pub decode_error: Option<String>,
}

impl ManifoldZmqReceivedMessage {
    /// Returns the UTF-8 payload text without the configured topic prefix.
    #[must_use]
    pub fn payload_text_without_topic(&self) -> Option<&str> {
        Some(strip_topic_prefix(
            self.utf8_text.as_deref()?,
            &self.topic_prefix,
        ))
    }

    /// Returns the raw message byte length.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.raw_bytes.len()
    }
}

/// Snapshot of a bounded ZeroMQ receiver queue.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifoldZmqReceiverSnapshot {
    /// Snapshot schema id.
    pub schema: String,
    /// Manifold bridge-route id.
    pub route_id: DottedId,
    /// Endpoint URL.
    pub endpoint: String,
    /// Topic prefix used by the receiver.
    pub topic_prefix: String,
    /// Receiver runtime status.
    pub status: ManifoldZmqReceiverStatus,
    /// Total messages accepted into the adapter.
    pub received_count: u64,
    /// Total messages drained by a consumer.
    pub drained_count: u64,
    /// Total messages dropped due to queue pressure.
    pub dropped_count: u64,
    /// Total messages with decode or topic-prefix issues.
    pub decode_error_count: u64,
    /// Current queued message count.
    pub queue_len: usize,
    /// Last receive timestamp.
    pub last_received_time_unix_ns: Option<u128>,
    /// Runtime fault text.
    pub fault: Option<String>,
}

/// Bounded queue shared by a runtime receiver and consumer loop.
#[derive(Clone, Debug)]
pub struct ManifoldZmqMessageInbox {
    shared: Arc<Mutex<InboxState>>,
}

#[derive(Debug)]
struct InboxState {
    config: ManifoldZmqPubSubReceiverConfig,
    status: ManifoldZmqReceiverStatus,
    queue: VecDeque<ManifoldZmqReceivedMessage>,
    next_sequence_number: u64,
    received_count: u64,
    drained_count: u64,
    dropped_count: u64,
    decode_error_count: u64,
    last_received_time_unix_ns: Option<u128>,
    fault: Option<String>,
}

impl ManifoldZmqMessageInbox {
    /// Creates an empty bounded inbox.
    #[must_use]
    pub fn new(config: ManifoldZmqPubSubReceiverConfig) -> Self {
        Self {
            shared: Arc::new(Mutex::new(InboxState {
                config,
                status: ManifoldZmqReceiverStatus::Starting,
                queue: VecDeque::new(),
                next_sequence_number: 0,
                received_count: 0,
                drained_count: 0,
                dropped_count: 0,
                decode_error_count: 0,
                last_received_time_unix_ns: None,
                fault: None,
            })),
        }
    }

    /// Pushes one raw message into the bounded queue.
    ///
    /// # Errors
    ///
    /// Returns [`ManifoldZmqAdapterError::MessageTooLarge`] when the message
    /// exceeds the configured maximum.
    pub fn push_raw_message(
        &self,
        raw_bytes: Vec<u8>,
        received_time_unix_ns: u128,
    ) -> Result<(), ManifoldZmqAdapterError> {
        let mut shared = self
            .shared
            .lock()
            .expect("ZeroMQ inbox state lock should not be poisoned");
        let max_message_bytes = shared.config.max_message_bytes.max(1);
        if raw_bytes.len() > max_message_bytes {
            return Err(ManifoldZmqAdapterError::MessageTooLarge {
                actual: raw_bytes.len(),
                max: max_message_bytes,
            });
        }

        let (utf8_text, mut decode_error) = match String::from_utf8(raw_bytes.clone()) {
            Ok(text) => (Some(text), None),
            Err(err) => (
                Some(String::from_utf8_lossy(err.as_bytes()).to_string()),
                Some(format!("message is not valid UTF-8: {err}")),
            ),
        };
        if decode_error.is_none() {
            decode_error = utf8_text
                .as_deref()
                .and_then(|text| validate_topic_prefix(text, &shared.config.topic_prefix));
        }
        if decode_error.is_some() {
            shared.decode_error_count = shared.decode_error_count.saturating_add(1);
        }

        let message = ManifoldZmqReceivedMessage {
            schema: MANIFOLD_ZMQ_RECEIVED_MESSAGE_SCHEMA.to_owned(),
            route_id: shared.config.route_id.clone(),
            endpoint: shared.config.endpoint.clone(),
            topic_prefix: shared.config.topic_prefix.clone(),
            sequence_number: shared.next_sequence_number,
            received_time_unix_ns,
            payload_encoding: shared.config.payload_encoding,
            payload_class: shared.config.payload_class,
            raw_bytes,
            utf8_text,
            decode_error,
        };
        shared.next_sequence_number = shared.next_sequence_number.saturating_add(1);
        push_message_locked(&mut shared, message);
        Ok(())
    }

    /// Drains all currently queued messages.
    pub fn drain_messages(&self) -> Vec<ManifoldZmqReceivedMessage> {
        let Ok(mut shared) = self.shared.lock() else {
            return Vec::new();
        };
        let drained: Vec<_> = shared.queue.drain(..).collect();
        shared.drained_count = shared.drained_count.saturating_add(drained.len() as u64);
        drained
    }

    /// Returns a point-in-time queue snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ManifoldZmqReceiverSnapshot {
        let shared = self
            .shared
            .lock()
            .expect("ZeroMQ inbox state lock should not be poisoned");
        ManifoldZmqReceiverSnapshot {
            schema: MANIFOLD_ZMQ_RECEIVER_SNAPSHOT_SCHEMA.to_owned(),
            route_id: shared.config.route_id.clone(),
            endpoint: shared.config.endpoint.clone(),
            topic_prefix: shared.config.topic_prefix.clone(),
            status: shared.status,
            received_count: shared.received_count,
            drained_count: shared.drained_count,
            dropped_count: shared.dropped_count,
            decode_error_count: shared.decode_error_count,
            queue_len: shared.queue.len(),
            last_received_time_unix_ns: shared.last_received_time_unix_ns,
            fault: shared.fault.clone(),
        }
    }

    /// Updates receiver status.
    pub fn set_status(&self, status: ManifoldZmqReceiverStatus) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.status = status;
        }
    }

    /// Records a terminal receiver fault.
    pub fn set_fault(&self, fault: impl Into<String>) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.status = ManifoldZmqReceiverStatus::Fault;
            shared.fault = Some(fault.into());
        }
    }
}

/// Runtime receiver handle available when `runtime` is enabled.
#[cfg(feature = "runtime")]
pub struct ManifoldZmqReceiverHandle {
    inbox: ManifoldZmqMessageInbox,
    shutdown_tx: Sender<()>,
    join_handle: Option<JoinHandle<()>>,
}

#[cfg(feature = "runtime")]
impl ManifoldZmqReceiverHandle {
    /// Returns the shared receiver inbox.
    #[must_use]
    pub fn inbox(&self) -> &ManifoldZmqMessageInbox {
        &self.inbox
    }

    /// Signals receiver shutdown and waits for the receiver thread.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(join_handle) = self.join_handle.take() {
            let _ = join_handle.join();
        }
    }
}

#[cfg(feature = "runtime")]
impl Drop for ManifoldZmqReceiverHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawns a background PUB/SUB receiver using the pure Rust `zeromq` crate.
#[cfg(feature = "runtime")]
pub fn spawn_pub_sub_receiver(
    config: ManifoldZmqPubSubReceiverConfig,
) -> io::Result<ManifoldZmqReceiverHandle> {
    let inbox = ManifoldZmqMessageInbox::new(config.clone());
    let thread_inbox = inbox.clone();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let join_handle = thread::Builder::new()
        .name("rusty-manifold-zmq-sub-receiver".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    thread_inbox.set_fault(format!("failed to create ZeroMQ runtime: {err}"));
                    return;
                }
            };
            runtime.block_on(receiver_loop(config, thread_inbox, shutdown_rx));
        })?;

    Ok(ManifoldZmqReceiverHandle {
        inbox,
        shutdown_tx,
        join_handle: Some(join_handle),
    })
}

/// Strips a configured topic prefix from a text message.
#[must_use]
pub fn strip_topic_prefix<'a>(raw_text: &'a str, topic_prefix: &str) -> &'a str {
    if topic_prefix.is_empty() {
        return raw_text;
    }
    let Some(rest) = raw_text.strip_prefix(topic_prefix) else {
        return raw_text;
    };
    if rest.is_empty() {
        rest
    } else if rest.starts_with(char::is_whitespace) {
        rest.trim_start()
    } else {
        raw_text
    }
}

fn validate_topic_prefix(raw_text: &str, topic_prefix: &str) -> Option<String> {
    if topic_prefix.is_empty() || raw_text.starts_with(topic_prefix) {
        None
    } else {
        Some(format!(
            "message does not start with topic prefix {topic_prefix:?}"
        ))
    }
}

fn push_message_locked(shared: &mut InboxState, message: ManifoldZmqReceivedMessage) {
    let capacity = shared.config.queue_capacity.max(1);
    if shared.queue.len() >= capacity {
        match shared.config.queue_policy {
            ManifoldQueueDropPolicy::DropOldest => {
                shared.queue.pop_front();
                shared.dropped_count = shared.dropped_count.saturating_add(1);
            }
            ManifoldQueueDropPolicy::DropNewest => {
                shared.dropped_count = shared.dropped_count.saturating_add(1);
                shared.received_count = shared.received_count.saturating_add(1);
                shared.last_received_time_unix_ns = Some(message.received_time_unix_ns);
                return;
            }
            ManifoldQueueDropPolicy::Backpressure => {
                shared.queue.pop_front();
                shared.dropped_count = shared.dropped_count.saturating_add(1);
            }
        }
    }
    shared.received_count = shared.received_count.saturating_add(1);
    shared.last_received_time_unix_ns = Some(message.received_time_unix_ns);
    shared.queue.push_back(message);
}

#[cfg(feature = "runtime")]
fn unix_time_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(feature = "runtime")]
async fn receiver_loop(
    config: ManifoldZmqPubSubReceiverConfig,
    inbox: ManifoldZmqMessageInbox,
    shutdown_rx: mpsc::Receiver<()>,
) {
    let mut socket = SubSocket::new();
    let setup_result = match config.open_mode {
        ManifoldZmqOpenMode::Bind => socket.bind(&config.endpoint).await.map(|_| ()),
        ManifoldZmqOpenMode::Connect => socket.connect(&config.endpoint).await,
    };
    if let Err(err) = setup_result {
        inbox.set_fault(format!("failed to open {}: {err}", config.endpoint));
        return;
    }
    if let Err(err) = socket.subscribe(&config.topic_prefix).await {
        inbox.set_fault(format!(
            "failed to subscribe to topic prefix {:?}: {err}",
            config.topic_prefix
        ));
        return;
    }

    inbox.set_status(ManifoldZmqReceiverStatus::Connected);
    let receive_timeout = Duration::from_millis(config.receive_timeout_ms.max(1));
    loop {
        match shutdown_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                inbox.set_status(ManifoldZmqReceiverStatus::Stopped);
                return;
            }
            Err(TryRecvError::Empty) => {}
        }

        match tokio::time::timeout(receive_timeout, socket.recv()).await {
            Ok(Ok(message)) => match message_to_bytes(message) {
                Ok(bytes) => {
                    if let Err(err) = inbox.push_raw_message(bytes, unix_time_ns()) {
                        inbox.set_fault(err.to_string());
                        return;
                    }
                }
                Err(err) => {
                    inbox.set_fault(err);
                    return;
                }
            },
            Ok(Err(err)) => {
                inbox.set_fault(format!("failed to receive ZeroMQ message: {err}"));
                return;
            }
            Err(_) => {}
        }
    }
}

#[cfg(feature = "runtime")]
fn message_to_bytes(message: ZmqMessage) -> Result<Vec<u8>, String> {
    Vec::<u8>::try_from(message).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_manifold_model::{
        ManifoldBridgeAuthorityRole, ManifoldBridgeConditionKind,
        ManifoldBridgeConditionRemediation, ManifoldBridgeConditionRequirement,
        ManifoldBridgeConditionScope, ManifoldBridgeConditionState,
        ManifoldBridgeDeliverySemantics, ManifoldBridgeEvidenceStage, ManifoldBridgePlane,
        ManifoldBridgeRouteKind, ManifoldBridgeRttStrategy, ManifoldBridgeTimingMetric,
        ManifoldBridgeTimingPolicy, StreamRateClass,
    };

    fn id(value: &str) -> DottedId {
        DottedId::new(value).expect("test id is valid")
    }

    fn route_conditions() -> Vec<ManifoldBridgeConditionRequirement> {
        vec![ManifoldBridgeConditionRequirement {
            condition_id: id("condition.tooling.zeromq.library"),
            scope: ManifoldBridgeConditionScope::Tooling,
            kind: ManifoldBridgeConditionKind::ProtocolLibraryAvailable,
            required_state: ManifoldBridgeConditionState::Available,
            check_ref: id("check.tooling.zeromq.library"),
            issue_codes: Vec::new(),
            remediation: Some(ManifoldBridgeConditionRemediation {
                action_ref: id("remediation.tooling.install_zeromq"),
                operator_label: "Install or enable ZeroMQ runtime support".to_owned(),
            }),
        }]
    }

    fn route_timing() -> ManifoldBridgeTimingPolicy {
        ManifoldBridgeTimingPolicy {
            rtt_strategy: ManifoldBridgeRttStrategy::ParallelLslClockEcho,
            clock_domain: id("clock.host_monotonic"),
            parallel_clock_route_id: Some(id("bridge_route.clock.lsl.roundtrip_echo")),
            min_round_trips: 8,
            timeout_ms: 5_000,
            warmup_ms: 250,
            reported_metrics: vec![
                ManifoldBridgeTimingMetric::RttMs,
                ManifoldBridgeTimingMetric::JitterMs,
                ManifoldBridgeTimingMetric::QueueDelayMs,
            ],
        }
    }

    fn route() -> ManifoldBridgeRouteDescriptor {
        ManifoldBridgeRouteDescriptor {
            schema_id: rusty_manifold_model::SchemaId::new(
                "rusty.manifold.bridge.route_descriptor.v1",
            )
            .expect("schema id is valid"),
            route_id: id("bridge_route.stream.zeromq.pub_sub"),
            route_kind: ManifoldBridgeRouteKind::StreamBridge,
            plane: ManifoldBridgePlane::Data,
            transport_family: ManifoldBridgeTransportFamily::ZeroMq,
            delivery: ManifoldBridgeDeliverySemantics::BestEffort,
            payload_class: ManifoldBridgePayloadClass::StreamPacket,
            rate_class: StreamRateClass::Periodic,
            authority_role: ManifoldBridgeAuthorityRole::Adapter,
            required_evidence_stages: vec![
                ManifoldBridgeEvidenceStage::Sent,
                ManifoldBridgeEvidenceStage::TransportOk,
                ManifoldBridgeEvidenceStage::Observed,
            ],
            fallback_route_ids: Vec::new(),
            issue_codes: Vec::new(),
            required_conditions: route_conditions(),
            timing: Some(route_timing()),
            zeromq: Some(rusty_manifold_model::ManifoldZeroMqRouteProfile {
                socket_pattern: ManifoldZeroMqSocketPattern::PubSub,
                endpoint_open_mode: ManifoldZeroMqEndpointOpenMode::Connect,
                endpoint_url: "tcp://127.0.0.1:5570".to_owned(),
                topic_prefix: "rusty.manifold.qcl084".to_owned(),
                payload_encoding: ManifoldZeroMqPayloadEncoding::Json,
                max_message_bytes: 1024,
                high_water_mark: 2,
                queue_policy: ManifoldQueueDropPolicy::DropOldest,
            }),
            lsl: None,
        }
    }

    #[test]
    fn config_derives_from_generic_zeromq_route() {
        let config = ManifoldZmqPubSubReceiverConfig::try_from_route(&route())
            .expect("route should configure receiver");

        assert_eq!(config.route_id, id("bridge_route.stream.zeromq.pub_sub"));
        assert_eq!(config.endpoint, "tcp://127.0.0.1:5570");
        assert_eq!(config.topic_prefix, "rusty.manifold.qcl084");
        assert_eq!(config.open_mode, ManifoldZmqOpenMode::Connect);
        assert_eq!(config.queue_capacity, 2);
        assert_eq!(config.max_message_bytes, 1024);
    }

    #[test]
    fn config_rejects_non_pub_sub_route() {
        let mut route = route();
        route
            .zeromq
            .as_mut()
            .expect("profile exists")
            .socket_pattern = ManifoldZeroMqSocketPattern::ReqRep;

        assert_eq!(
            ManifoldZmqPubSubReceiverConfig::try_from_route(&route),
            Err(ManifoldZmqAdapterError::UnsupportedPattern(
                ManifoldZeroMqSocketPattern::ReqRep
            ))
        );
    }

    #[test]
    fn inbox_drops_oldest_when_bounded() {
        let config = ManifoldZmqPubSubReceiverConfig::try_from_route(&route())
            .expect("route should configure receiver");
        let inbox = ManifoldZmqMessageInbox::new(config);

        inbox
            .push_raw_message(b"rusty.manifold.qcl084 {\"sequence\":1}".to_vec(), 100)
            .expect("message fits");
        inbox
            .push_raw_message(b"rusty.manifold.qcl084 {\"sequence\":2}".to_vec(), 101)
            .expect("message fits");
        inbox
            .push_raw_message(b"rusty.manifold.qcl084 {\"sequence\":3}".to_vec(), 102)
            .expect("message fits");

        let snapshot = inbox.snapshot();
        assert_eq!(snapshot.received_count, 3);
        assert_eq!(snapshot.dropped_count, 1);
        assert_eq!(snapshot.queue_len, 2);

        let drained = inbox.drain_messages();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].sequence_number, 1);
        assert_eq!(drained[1].sequence_number, 2);
        assert_eq!(
            drained[0].payload_text_without_topic(),
            Some("{\"sequence\":2}")
        );
    }

    #[test]
    fn topic_prefix_validation_is_reported_without_dropping_payload() {
        let config = ManifoldZmqPubSubReceiverConfig::try_from_route(&route())
            .expect("route should configure receiver");
        let inbox = ManifoldZmqMessageInbox::new(config);

        inbox
            .push_raw_message(b"other.topic {\"sequence\":1}".to_vec(), 100)
            .expect("message fits");

        let drained = inbox.drain_messages();
        assert!(drained[0].decode_error.is_some());
        assert_eq!(
            drained[0].payload_text_without_topic(),
            Some("other.topic {\"sequence\":1}")
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_snapshot_when_enabled() {
        let config = ManifoldZmqPubSubReceiverConfig::try_from_route(&route())
            .expect("route should configure receiver");
        let inbox = ManifoldZmqMessageInbox::new(config);
        let snapshot = inbox.snapshot();

        let json = serde_json::to_string(&snapshot).expect("snapshot should serialize");
        let decoded: ManifoldZmqReceiverSnapshot =
            serde_json::from_str(&json).expect("snapshot should deserialize");
        assert_eq!(decoded, snapshot);
    }
}
