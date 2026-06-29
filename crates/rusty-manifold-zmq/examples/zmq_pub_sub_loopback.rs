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
use serde_json::{json, Value};
use std::{
    env,
    error::Error,
    io,
    net::TcpListener,
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeromq::{PubSocket, Socket, SocketSend, ZmqMessage};

const TOPIC_PREFIX: &str = "rusty.manifold.qcl084";
const DEFAULT_SAMPLE_COUNT: usize = 5;
const REPORT_SCHEMA: &str = "rusty.manifold.zmq.qcl084_pub_sub_loopback_report.v1";

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse()?;
    let port = reserve_loopback_port()?;
    let endpoint = format!("tcp://127.0.0.1:{port}");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(run_loopback(endpoint, args))
}

async fn run_loopback(endpoint: String, args: Args) -> Result<(), Box<dyn Error>> {
    let started_at_ms = unix_time_ms();
    let started = Instant::now();
    let mut publisher = PubSocket::new();
    publisher.bind(&endpoint).await?;

    let route = manifold_zeromq_route(endpoint.clone());
    let config =
        ManifoldZmqPubSubReceiverConfig::try_from_route(&route)?.with_receive_timeout_ms(10);
    let receiver = spawn_pub_sub_receiver(config)?;
    wait_for_connected(receiver.inbox(), Duration::from_secs(2)).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    for sequence_number in 0..args.message_count {
        let payload = format!(
            "{TOPIC_PREFIX} {{\"sequence_number\":{sequence_number},\"source\":\"synthetic\"}}"
        );
        publisher.send(ZmqMessage::from(payload)).await?;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let messages =
        drain_until(receiver.inbox(), args.message_count, Duration::from_secs(2)).await?;
    let snapshot = receiver.inbox().snapshot();
    let ended_at_ms = unix_time_ms();
    let close_errors = publisher.close().await;
    receiver.shutdown();

    if !close_errors.is_empty() {
        return Err(io_error(
            io::ErrorKind::Other,
            format!("failed to close ZeroMQ publisher cleanly: {close_errors:?}"),
        ));
    }

    let status = if snapshot.received_count as usize >= args.message_count
        && snapshot.drained_count as usize >= args.message_count
        && snapshot.dropped_count == 0
        && snapshot.decode_error_count == 0
    {
        "pass"
    } else if snapshot.drained_count > 0 {
        "warn"
    } else {
        "fail"
    };
    let report = loopback_report(
        &args,
        &route,
        &endpoint,
        &snapshot,
        &messages,
        status,
        started_at_ms,
        ended_at_ms,
        started.elapsed(),
    );

    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
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
    }

    if status == "pass" {
        Ok(())
    } else {
        Err(io_error(
            io::ErrorKind::Other,
            format!("ZeroMQ loopback finished with status {status}"),
        ))
    }
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

fn loopback_report(
    args: &Args,
    route: &ManifoldBridgeRouteDescriptor,
    endpoint: &str,
    snapshot: &rusty_manifold_zmq::ManifoldZmqReceiverSnapshot,
    messages: &[ManifoldZmqReceivedMessage],
    status: &str,
    started_at_ms: u128,
    ended_at_ms: u128,
    duration: Duration,
) -> Value {
    let received_sequences: Vec<u64> = messages
        .iter()
        .map(|message| message.sequence_number)
        .collect();
    let evidence_tier = if args.source == "native-rust-broker" {
        "broker_owned"
    } else {
        "host_loopback"
    };
    let issue_codes: Vec<&str> = match status {
        "pass" => Vec::new(),
        "warn" => vec!["rusty.manifold.issue.qcl084_zeromq_exchange_degraded"],
        _ => vec!["rusty.manifold.issue.qcl084_zeromq_exchange_failed"],
    };
    json!({
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "status": status,
        "source": args.source,
        "evidence_tier": evidence_tier,
        "pattern": "pub-sub",
        "route_id": route.route_id.to_string(),
        "endpoint": endpoint,
        "topic_prefix": TOPIC_PREFIX,
        "authority": {
            "owner": "rusty.manifold.transport",
            "route_authority_role": "adapter",
            "route_descriptor_owned_by": "rusty-manifold",
            "runtime_adapter": "rusty-manifold-zmq",
        },
        "messages_requested": args.message_count,
        "messages_received": snapshot.received_count,
        "messages_acknowledged": snapshot.drained_count,
        "dropped_count": snapshot.dropped_count,
        "decode_error_count": snapshot.decode_error_count,
        "received_sequences": received_sequences,
        "duration_ms": duration.as_millis(),
        "round_trip_ms_p95": Value::Null,
        "issue_codes": issue_codes,
        "bridge_route_evidence": {
            "$schema": "rusty.manifold.bridge.route_evidence.v1",
            "evidence_id": format!("evidence.bridge_route.stream.zeromq.pub_sub.{}", args.source.replace('-', "_")),
            "route_id": route.route_id.to_string(),
            "status": status,
            "started_at_ms": started_at_ms,
            "ended_at_ms": ended_at_ms,
            "stage_reports": [
                {
                    "stage": "sent",
                    "status": status,
                    "observed_at_ms": started_at_ms,
                    "evidence_refs": ["evidence.zeromq.publisher.sent"],
                    "issue_codes": issue_codes,
                },
                {
                    "stage": "transport_ok",
                    "status": if snapshot.status == ManifoldZmqReceiverStatus::Fault { "fail" } else { status },
                    "observed_at_ms": started_at_ms,
                    "evidence_refs": ["evidence.zeromq.subscriber.connected"],
                    "issue_codes": issue_codes,
                },
                {
                    "stage": "observed",
                    "status": status,
                    "observed_at_ms": ended_at_ms,
                    "evidence_refs": ["evidence.zeromq.subscriber.received"],
                    "issue_codes": issue_codes,
                }
            ],
            "artifact_refs": ["artifact.zeromq.loopback.report"],
            "issues": issue_codes,
        },
    })
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

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn io_error(kind: io::ErrorKind, message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(kind, message.into()))
}

#[derive(Debug)]
struct Args {
    json: bool,
    source: String,
    message_count: usize,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut parsed = Self {
            json: false,
            source: "manifold-zmq-loopback".to_owned(),
            message_count: DEFAULT_SAMPLE_COUNT,
        };
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--json" => parsed.json = true,
                "--source" => {
                    parsed.source = args.next().ok_or("missing value for argument --source")?;
                }
                "--message-count" => {
                    let value = args
                        .next()
                        .ok_or("missing value for argument --message-count")?;
                    parsed.message_count = parse_value(&flag, &value)?;
                    if parsed.message_count == 0 {
                        return Err("--message-count must be greater than zero".into());
                    }
                }
                _ => return Err(format!("unsupported argument {flag}").into()),
            }
        }
        Ok(parsed)
    }
}

fn parse_value<T>(flag: &str, value: &str) -> Result<T, Box<dyn Error>>
where
    T: FromStr,
    T::Err: Error + 'static,
{
    value
        .parse::<T>()
        .map_err(|err| format!("{flag} value {value:?} is invalid: {err}").into())
}
