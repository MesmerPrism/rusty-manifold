//! Host-local PUB/SUB loopback for the Manifold ZeroMQ adapter.

use rusty_manifold_model::{
    DottedId, ManifoldBridgeAuthorityRole, ManifoldBridgeConditionKind,
    ManifoldBridgeConditionRemediation, ManifoldBridgeConditionRequirement,
    ManifoldBridgeConditionScope, ManifoldBridgeConditionState, ManifoldBridgeDeliverySemantics,
    ManifoldBridgeEvidenceStage, ManifoldBridgePayloadClass, ManifoldBridgePlane,
    ManifoldBridgeRouteDescriptor, ManifoldBridgeRouteKind, ManifoldBridgeRttStrategy,
    ManifoldBridgeTimingMetric, ManifoldBridgeTimingPolicy, ManifoldBridgeTransportFamily,
    ManifoldQueueDropPolicy, ManifoldZeroMqEndpointOpenMode, ManifoldZeroMqPayloadEncoding,
    ManifoldZeroMqRouteProfile, ManifoldZeroMqSocketPattern, SchemaId, StreamRateClass,
};
use rusty_manifold_zmq::{
    spawn_pub_sub_receiver, ManifoldZmqMessageInbox, ManifoldZmqPubSubReceiverConfig,
    ManifoldZmqReceivedMessage, ManifoldZmqReceiverStatus,
};
use std::{
    error::Error,
    io,
    net::TcpListener,
    time::{Duration, Instant},
};
use zeromq::{PubSocket, Socket, SocketSend, ZmqMessage};

const TOPIC_PREFIX: &str = "rusty.manifold.qcl084";
const SAMPLE_COUNT: usize = 5;

fn main() -> Result<(), Box<dyn Error>> {
    let port = reserve_loopback_port()?;
    let endpoint = format!("tcp://127.0.0.1:{port}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(run_loopback(endpoint))
}

async fn run_loopback(endpoint: String) -> Result<(), Box<dyn Error>> {
    let mut publisher = PubSocket::new();
    publisher.bind(&endpoint).await?;

    let route = manifold_zeromq_route(endpoint.clone());
    let config =
        ManifoldZmqPubSubReceiverConfig::try_from_route(&route)?.with_receive_timeout_ms(10);
    let receiver = spawn_pub_sub_receiver(config)?;
    wait_for_connected(receiver.inbox(), Duration::from_secs(2)).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    for sequence_number in 0..SAMPLE_COUNT {
        let payload = format!(
            "{TOPIC_PREFIX} {{\"sequence_number\":{sequence_number},\"source\":\"synthetic\"}}"
        );
        publisher.send(ZmqMessage::from(payload)).await?;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let messages = drain_until(receiver.inbox(), SAMPLE_COUNT, Duration::from_secs(2)).await?;
    let snapshot = receiver.inbox().snapshot();
    let close_errors = publisher.close().await;
    receiver.shutdown();

    if !close_errors.is_empty() {
        return Err(io_error(
            io::ErrorKind::Other,
            format!("failed to close ZeroMQ publisher cleanly: {close_errors:?}"),
        ));
    }

    println!("ZeroMQ loopback endpoint: {endpoint}");
    println!(
        "received={} drained={} dropped={} decode_errors={}",
        snapshot.received_count,
        snapshot.drained_count,
        snapshot.dropped_count,
        snapshot.decode_error_count
    );
    for message in messages {
        println!(
            "{} {}",
            message.sequence_number,
            message.utf8_text.as_deref().unwrap_or("<non-utf8>")
        );
    }

    Ok(())
}

fn manifold_zeromq_route(endpoint: String) -> ManifoldBridgeRouteDescriptor {
    ManifoldBridgeRouteDescriptor {
        schema_id: SchemaId::new("rusty.manifold.bridge.route_descriptor.v1")
            .expect("schema literal is valid"),
        route_id: DottedId::new("bridge_route.stream.zeromq.pub_sub").expect("id literal is valid"),
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
        required_conditions: vec![ManifoldBridgeConditionRequirement {
            condition_id: DottedId::new("condition.tooling.zeromq.library")
                .expect("id literal is valid"),
            scope: ManifoldBridgeConditionScope::Tooling,
            kind: ManifoldBridgeConditionKind::ProtocolLibraryAvailable,
            required_state: ManifoldBridgeConditionState::Available,
            check_ref: DottedId::new("check.tooling.zeromq.library").expect("id literal is valid"),
            issue_codes: Vec::new(),
            remediation: Some(ManifoldBridgeConditionRemediation {
                action_ref: DottedId::new("remediation.tooling.install_zeromq")
                    .expect("id literal is valid"),
                operator_label: "Install or enable ZeroMQ runtime support".to_owned(),
            }),
        }],
        timing: Some(ManifoldBridgeTimingPolicy {
            rtt_strategy: ManifoldBridgeRttStrategy::ParallelLslClockEcho,
            clock_domain: DottedId::new("clock.host_monotonic").expect("id literal is valid"),
            parallel_clock_route_id: Some(
                DottedId::new("bridge_route.clock.lsl.roundtrip_echo")
                    .expect("id literal is valid"),
            ),
            min_round_trips: 8,
            timeout_ms: 5_000,
            warmup_ms: 250,
            reported_metrics: vec![
                ManifoldBridgeTimingMetric::RttMs,
                ManifoldBridgeTimingMetric::JitterMs,
                ManifoldBridgeTimingMetric::QueueDelayMs,
            ],
        }),
        zeromq: Some(ManifoldZeroMqRouteProfile {
            socket_pattern: ManifoldZeroMqSocketPattern::PubSub,
            endpoint_open_mode: ManifoldZeroMqEndpointOpenMode::Connect,
            endpoint_url: endpoint,
            topic_prefix: TOPIC_PREFIX.to_owned(),
            payload_encoding: ManifoldZeroMqPayloadEncoding::Json,
            max_message_bytes: 4096,
            high_water_mark: 16,
            queue_policy: ManifoldQueueDropPolicy::DropOldest,
        }),
        lsl: None,
    }
}

async fn wait_for_connected(
    inbox: &ManifoldZmqMessageInbox,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    loop {
        let snapshot = inbox.snapshot();
        match snapshot.status {
            ManifoldZmqReceiverStatus::Connected => return Ok(()),
            ManifoldZmqReceiverStatus::Fault => {
                return Err(io_error(
                    io::ErrorKind::Other,
                    format!("ZeroMQ receiver fault: {:?}", snapshot.fault),
                ));
            }
            ManifoldZmqReceiverStatus::Starting | ManifoldZmqReceiverStatus::Stopped => {}
        }
        if start.elapsed() >= timeout {
            return Err(io_error(
                io::ErrorKind::TimedOut,
                "timed out waiting for ZeroMQ receiver connection",
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn drain_until(
    inbox: &ManifoldZmqMessageInbox,
    expected_count: usize,
    timeout: Duration,
) -> Result<Vec<ManifoldZmqReceivedMessage>, Box<dyn Error>> {
    let start = Instant::now();
    let mut messages = Vec::with_capacity(expected_count);
    loop {
        messages.extend(inbox.drain_messages());
        if messages.len() >= expected_count {
            return Ok(messages);
        }

        let snapshot = inbox.snapshot();
        if snapshot.status == ManifoldZmqReceiverStatus::Fault {
            return Err(io_error(
                io::ErrorKind::Other,
                format!("ZeroMQ receiver fault: {:?}", snapshot.fault),
            ));
        }
        if start.elapsed() >= timeout {
            return Err(io_error(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for ZeroMQ loopback messages: got {}, expected {expected_count}",
                    messages.len()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn reserve_loopback_port() -> io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn io_error(kind: io::ErrorKind, message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(kind, message.into()))
}
