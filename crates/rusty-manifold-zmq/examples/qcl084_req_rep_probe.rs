//! QCL-084 headset-capable REQ/REP ZeroMQ probe.
//!
//! This is intentionally an example binary, not a core Manifold dependency.
//! It exercises the pure-Rust `zeromq` adapter on either a host or Android
//! target and emits bounded JSON evidence for Hostess connectivity reports.

use serde_json::{json, Value};
use std::{
    env,
    error::Error,
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeromq::{RepSocket, ReqSocket, Socket, SocketRecv, SocketSend, ZmqMessage};

const SCHEMA: &str = "rusty.manifold.zmq.qcl084_req_rep_probe.v1";
const DEFAULT_ENDPOINT: &str = "tcp://127.0.0.1:18784";
const DEFAULT_RUN_ID: &str = "qcl084-req-rep";
const DEFAULT_MESSAGE_COUNT: usize = 16;
const DEFAULT_TIMEOUT_MS: u64 = 12_000;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(async {
        match args.role.as_str() {
            "server" => run_server(&args).await,
            "client" => run_client(&args).await,
            role => Err(format!("unsupported role {role:?}; expected server or client").into()),
        }
    })?;
    println!("{}", serde_json::to_string(&report)?);
    if report.get("status").and_then(Value::as_str) == Some("pass") {
        Ok(())
    } else {
        Err("QCL-084 probe did not pass".into())
    }
}

async fn run_server(args: &Args) -> Result<Value, Box<dyn Error>> {
    let started_at = now_unix_ns();
    let started = Instant::now();
    let timeout = Duration::from_millis(args.timeout_ms);
    let deadline = Instant::now() + timeout;
    let mut socket = RepSocket::new();
    socket.bind(&args.endpoint).await?;
    eprintln!(
        "QCL084_READY role=server endpoint={} run_id={}",
        args.endpoint, args.run_id
    );

    let mut received_sequences = Vec::with_capacity(args.message_count);
    let mut ack_sequences = Vec::with_capacity(args.message_count);
    let mut errors = Vec::new();
    while received_sequences.len() < args.message_count && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let recv_result =
            tokio::time::timeout(remaining.min(Duration::from_millis(500)), socket.recv()).await;
        let request = match recv_result {
            Ok(Ok(message)) => message,
            Ok(Err(err)) => {
                errors.push(err.to_string());
                continue;
            }
            Err(_) => continue,
        };
        let receive_ns = monotonic_ns(started);
        let request_text = message_to_string(request)?;
        let request_json: Value = serde_json::from_str(&request_text)?;
        let sequence = request_json
            .get("sequence")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        received_sequences.push(sequence);
        let send_ns = monotonic_ns(started);
        let reply = json!({
            "schema": SCHEMA,
            "role": "server_reply",
            "run_id": args.run_id,
            "status": "ack",
            "sequence": sequence,
            "host_send_monotonic_ns": request_json.get("host_send_monotonic_ns").and_then(Value::as_u64),
            "server_received_elapsed_ns": receive_ns,
            "server_send_elapsed_ns": send_ns,
            "server_wall_time_ns": now_unix_ns(),
        });
        socket.send(ZmqMessage::from(reply.to_string())).await?;
        ack_sequences.push(sequence);
    }
    let close_errors = socket.close().await;
    for error in close_errors {
        errors.push(format!("{error:?}"));
    }

    let received = received_sequences.len();
    let acknowledged = ack_sequences.len();
    let loss_percent = loss_percent(args.message_count, acknowledged);
    let status = if received >= args.message_count
        && acknowledged >= args.message_count
        && errors.is_empty()
    {
        "pass"
    } else if acknowledged > 0 {
        "warn"
    } else {
        "fail"
    };
    Ok(json!({
        "schema": SCHEMA,
        "schema_version": 1,
        "role": "server",
        "status": status,
        "run_id": args.run_id,
        "endpoint": args.endpoint,
        "messages_requested": args.message_count,
        "messages_received": received,
        "messages_acknowledged": acknowledged,
        "loss_percent": loss_percent,
        "started_wall_time_ns": started_at,
        "duration_ms": started.elapsed().as_millis(),
        "received_sequences": received_sequences,
        "acknowledged_sequences": ack_sequences,
        "errors": errors,
        "issue_codes": issue_codes(status, acknowledged),
    }))
}

async fn run_client(args: &Args) -> Result<Value, Box<dyn Error>> {
    let started_at = now_unix_ns();
    let started = Instant::now();
    let timeout = Duration::from_millis(args.timeout_ms);
    let mut socket = ReqSocket::new();
    socket.connect(&args.endpoint).await?;
    tokio::time::sleep(Duration::from_millis(args.connect_settle_ms)).await;

    let mut acknowledged_sequences = Vec::with_capacity(args.message_count);
    let mut received_sequences = Vec::with_capacity(args.message_count);
    let mut timing_samples = Vec::with_capacity(args.message_count);
    let mut rtts = Vec::with_capacity(args.message_count);
    let mut server_processing = Vec::with_capacity(args.message_count);
    let mut clock_offsets = Vec::with_capacity(args.message_count);
    let mut errors = Vec::new();

    for sequence in 0..args.message_count {
        let host_send_ns = monotonic_ns(started);
        let request = json!({
            "schema": SCHEMA,
            "role": "client_request",
            "run_id": args.run_id,
            "sequence": sequence,
            "host_send_monotonic_ns": host_send_ns,
            "host_wall_time_ns": now_unix_ns(),
        });
        if let Err(err) = socket.send(ZmqMessage::from(request.to_string())).await {
            errors.push(err.to_string());
            break;
        }
        let recv_result = tokio::time::timeout(timeout, socket.recv()).await;
        let host_receive_ns = monotonic_ns(started);
        let reply = match recv_result {
            Ok(Ok(message)) => message,
            Ok(Err(err)) => {
                errors.push(err.to_string());
                break;
            }
            Err(_) => {
                errors.push(format!("timed out waiting for reply sequence {sequence}"));
                break;
            }
        };
        let reply_text = message_to_string(reply)?;
        let reply_json: Value = serde_json::from_str(&reply_text)?;
        let reply_sequence = reply_json
            .get("sequence")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX) as usize;
        received_sequences.push(reply_sequence);
        if reply_sequence == sequence
            && reply_json.get("status").and_then(Value::as_str) == Some("ack")
        {
            acknowledged_sequences.push(sequence);
        }
        let rtt_ms = (host_receive_ns.saturating_sub(host_send_ns)) as f64 / 1_000_000.0;
        let server_received_ns = reply_json
            .get("server_received_elapsed_ns")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let server_send_ns = reply_json
            .get("server_send_elapsed_ns")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let processing_ms = server_send_ns.saturating_sub(server_received_ns) as f64 / 1_000_000.0;
        let clock_offset_ms = ((server_received_ns as i128 - host_send_ns as i128)
            + (server_send_ns as i128 - host_receive_ns as i128))
            as f64
            / 2_000_000.0;
        let one_way_ms = ((rtt_ms - processing_ms) / 2.0).max(0.0);
        rtts.push(rtt_ms);
        server_processing.push(processing_ms);
        clock_offsets.push(clock_offset_ms);
        timing_samples.push(json!({
            "sequence": sequence,
            "round_trip_ms": round3(rtt_ms),
            "server_processing_ms": round3(processing_ms),
            "estimated_one_way_ms": round3(one_way_ms),
            "clock_offset_estimate_ms": round3(clock_offset_ms),
        }));
        tokio::time::sleep(Duration::from_millis(args.interval_ms)).await;
    }
    let close_errors = socket.close().await;
    for error in close_errors {
        errors.push(format!("{error:?}"));
    }

    let acknowledged = acknowledged_sequences.len();
    let loss_percent = loss_percent(args.message_count, acknowledged);
    let monotonic = acknowledged_sequences
        .iter()
        .enumerate()
        .all(|(index, sequence)| *sequence == index);
    let status = if acknowledged == args.message_count && monotonic && errors.is_empty() {
        "pass"
    } else if acknowledged > 0 {
        "warn"
    } else {
        "fail"
    };
    let median_offset = median(&clock_offsets);
    let offset_jitter: Vec<f64> = median_offset
        .map(|median| {
            clock_offsets
                .iter()
                .map(|value| (value - median).abs())
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({
        "schema": SCHEMA,
        "schema_version": 1,
        "role": "client",
        "status": status,
        "run_id": args.run_id,
        "endpoint": args.endpoint,
        "messages_requested": args.message_count,
        "messages_received": received_sequences.len(),
        "messages_acknowledged": acknowledged,
        "loss_percent": loss_percent,
        "round_trip_ms_p95": percentile(&rtts, 95).map(round3),
        "round_trip_ms_max": rtts.iter().copied().reduce(f64::max).map(round3),
        "server_processing_ms_p95": percentile(&server_processing, 95).map(round3),
        "estimated_one_way_ms_p95": percentile(
            &timing_samples
                .iter()
                .filter_map(|sample| sample.get("estimated_one_way_ms").and_then(Value::as_f64))
                .collect::<Vec<_>>(),
            95,
        ).map(round3),
        "clock_offset_estimate_ms_median": median_offset.map(round3),
        "clock_offset_jitter_ms_p95": percentile(&offset_jitter, 95).map(round3),
        "started_wall_time_ns": started_at,
        "duration_ms": started.elapsed().as_millis(),
        "monotonic_sequences": monotonic,
        "received_sequences": received_sequences,
        "acknowledged_sequences": acknowledged_sequences,
        "timing_samples": timing_samples,
        "errors": errors,
        "issue_codes": issue_codes(status, acknowledged),
    }))
}

fn message_to_string(message: ZmqMessage) -> Result<String, Box<dyn Error>> {
    String::try_from(message).map_err(Into::into)
}

fn now_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn monotonic_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

fn loss_percent(requested: usize, acknowledged: usize) -> f64 {
    if requested == 0 {
        return 100.0;
    }
    round3(((requested.saturating_sub(acknowledged)) as f64 / requested as f64) * 100.0)
}

fn percentile(values: &[f64], percentile_value: u32) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|left, right| left.total_cmp(right));
    let index = (((percentile_value as f64 / 100.0) * (ordered.len().saturating_sub(1)) as f64)
        .round() as usize)
        .min(ordered.len() - 1);
    Some(ordered[index])
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|left, right| left.total_cmp(right));
    let midpoint = ordered.len() / 2;
    if ordered.len() % 2 == 1 {
        Some(ordered[midpoint])
    } else {
        Some((ordered[midpoint - 1] + ordered[midpoint]) / 2.0)
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn issue_codes(status: &str, acknowledged: usize) -> Vec<&'static str> {
    match (status, acknowledged > 0) {
        ("pass", _) => Vec::new(),
        ("warn", _) => vec!["rusty.manifold.issue.qcl084_zeromq_exchange_degraded"],
        (_, true) => vec!["rusty.manifold.issue.qcl084_zeromq_exchange_degraded"],
        _ => vec!["rusty.manifold.issue.qcl084_zeromq_exchange_failed"],
    }
}

#[derive(Debug)]
struct Args {
    role: String,
    endpoint: String,
    run_id: String,
    message_count: usize,
    timeout_ms: u64,
    interval_ms: u64,
    connect_settle_ms: u64,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut args = env::args().skip(1);
        let role = args
            .next()
            .ok_or("usage: qcl084_req_rep_probe <server|client> [--endpoint tcp://host:port]")?;
        let mut parsed = Self {
            role,
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            run_id: DEFAULT_RUN_ID.to_owned(),
            message_count: DEFAULT_MESSAGE_COUNT,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            interval_ms: 5,
            connect_settle_ms: 250,
        };
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for argument {flag}"))?;
            match flag.as_str() {
                "--endpoint" => parsed.endpoint = value,
                "--run-id" => parsed.run_id = value,
                "--message-count" => parsed.message_count = parse_value(&flag, &value)?,
                "--timeout-ms" => parsed.timeout_ms = parse_value(&flag, &value)?,
                "--interval-ms" => parsed.interval_ms = parse_value(&flag, &value)?,
                "--connect-settle-ms" => parsed.connect_settle_ms = parse_value(&flag, &value)?,
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
