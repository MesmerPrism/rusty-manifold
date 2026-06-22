use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use super::{CliError, ManifoldScalarF32Sample};

const COMMAND_SCHEMA: &str = "rusty.manifold.command.envelope.v1";
const CLIENT_ID: &str = "rusty-manifold-fixtures.synthetic-scalar-publisher";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SyntheticScalarPublishConfig {
    pub(super) broker_host: String,
    pub(super) broker_port: u16,
    pub(super) broker_path: String,
    pub(super) sample_interval: Option<Duration>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct SyntheticScalarPublishReport {
    #[serde(rename = "$schema")]
    pub(super) schema_id: String,
    pub(super) broker_url: String,
    pub(super) stream_id: String,
    pub(super) source_module_id: String,
    pub(super) sample_count: usize,
    pub(super) accepted_count: usize,
    pub(super) published_count: usize,
    pub(super) first_sequence_id: Option<u64>,
    pub(super) last_sequence_id: Option<u64>,
    pub(super) slept_between_samples: bool,
}

pub(super) fn publish_synthetic_scalar_samples(
    config: &SyntheticScalarPublishConfig,
    samples: &[ManifoldScalarF32Sample],
) -> Result<SyntheticScalarPublishReport, CliError> {
    let mut socket = BrokerSocket::connect(
        &config.broker_host,
        config.broker_port,
        &config.broker_path,
        Duration::from_secs(2),
    )?;
    let mut accepted_count = 0usize;
    let mut published_count = 0usize;
    for (index, sample) in samples.iter().enumerate() {
        let payload = serde_json::to_value(sample).map_err(CliError::Serialize)?;
        let command = json!({
            "type": "command",
            "schema": COMMAND_SCHEMA,
            "request_id": format!("request.synthetic_scalar_publish.{}", sample.sequence_id),
            "command": "publish_stream_event",
            "params": {
                "stream": sample.stream_id,
                "stream_id": sample.stream_id,
                "sequence_id": sample.sequence_id,
                "payload": payload
            },
            "client_id": CLIENT_ID
        });
        socket.send_json(&command)?;
        let ack = socket.recv_json(Duration::from_secs(2))?.ok_or_else(|| {
            CliError::Transport("broker did not acknowledge synthetic scalar sample".to_owned())
        })?;
        if ack
            .get("accepted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            accepted_count += 1;
        }
        if ack
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "published")
        {
            published_count += 1;
        }

        if let Some(interval) = config.sample_interval {
            if index + 1 < samples.len() && !interval.is_zero() {
                std::thread::sleep(interval);
            }
        }
    }

    Ok(SyntheticScalarPublishReport {
        schema_id: "rusty.manifold.synthetic.scalar_publish_report.v1".to_owned(),
        broker_url: format!(
            "ws://{}:{}{}",
            config.broker_host, config.broker_port, config.broker_path
        ),
        stream_id: samples
            .first()
            .map(|sample| sample.stream_id.to_string())
            .unwrap_or_default(),
        source_module_id: samples
            .first()
            .map(|sample| sample.source_module_id.to_string())
            .unwrap_or_default(),
        sample_count: samples.len(),
        accepted_count,
        published_count,
        first_sequence_id: samples.first().map(|sample| sample.sequence_id),
        last_sequence_id: samples.last().map(|sample| sample.sequence_id),
        slept_between_samples: config
            .sample_interval
            .is_some_and(|interval| !interval.is_zero()),
    })
}

struct BrokerSocket {
    stream: TcpStream,
}

impl BrokerSocket {
    fn connect(host: &str, port: u16, path: &str, timeout: Duration) -> Result<Self, CliError> {
        let mut stream = TcpStream::connect((host, port)).map_err(|source| {
            CliError::Transport(format!("connect ws://{host}:{port}{path}: {source}"))
        })?;
        stream.set_read_timeout(Some(timeout)).map_err(|source| {
            CliError::Transport(format!("set websocket read timeout: {source}"))
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|source| {
            CliError::Transport(format!("set websocket write timeout: {source}"))
        })?;
        let key = "cnVzdHktbWFuaWZvbGQtc3ludGg=";
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|source| CliError::Transport(format!("send websocket handshake: {source}")))?;
        let response = read_http_response(&mut stream)?;
        if !response.starts_with("HTTP/1.1 101") && !response.starts_with("HTTP/1.0 101") {
            return Err(CliError::Transport(format!(
                "broker websocket handshake failed: {}",
                response.lines().next().unwrap_or("empty-response")
            )));
        }
        Ok(Self { stream })
    }

    fn send_json(&mut self, payload: &Value) -> Result<(), CliError> {
        let text = serde_json::to_vec(payload).map_err(CliError::Serialize)?;
        self.send_frame(0x1, &text)
    }

    fn recv_json(&mut self, timeout: Duration) -> Result<Option<Value>, CliError> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|source| {
                CliError::Transport(format!("set websocket poll timeout: {source}"))
            })?;
        let (opcode, payload) = match self.recv_frame() {
            Ok(frame) => frame,
            Err(error) if error.contains("WouldBlock") || error.contains("timed out") => {
                return Ok(None);
            }
            Err(error) => return Err(CliError::Transport(error)),
        };
        match opcode {
            0x1 => serde_json::from_slice(&payload)
                .map(Some)
                .map_err(CliError::Serialize),
            0x8 => Err(CliError::Transport("broker websocket closed".to_owned())),
            0x9 => {
                let _ = self.send_frame(0xA, &payload);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), CliError> {
        let mut header = Vec::new();
        header.push(0x80 | (opcode & 0x0F));
        if payload.len() < 126 {
            header.push(0x80 | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            header.push(0x80 | 126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        let mask = websocket_mask();
        let masked = payload
            .iter()
            .enumerate()
            .map(|(index, value)| value ^ mask[index % 4])
            .collect::<Vec<_>>();
        self.stream
            .write_all(&header)
            .and_then(|_| self.stream.write_all(&mask))
            .and_then(|_| self.stream.write_all(&masked))
            .map_err(|source| CliError::Transport(format!("send websocket frame: {source}")))
    }

    fn recv_frame(&mut self) -> Result<(u8, Vec<u8>), String> {
        let header = read_exact(&mut self.stream, 2)?;
        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let mut length = (header[1] & 0x7F) as usize;
        if length == 126 {
            length =
                u16::from_be_bytes(read_exact(&mut self.stream, 2)?.try_into().unwrap()) as usize;
        } else if length == 127 {
            length =
                u64::from_be_bytes(read_exact(&mut self.stream, 8)?.try_into().unwrap()) as usize;
        }
        let mask = if masked {
            read_exact(&mut self.stream, 4)?
        } else {
            Vec::new()
        };
        let mut payload = if length == 0 {
            Vec::new()
        } else {
            read_exact(&mut self.stream, length)?
        };
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        Ok((opcode, payload))
    }
}

fn read_http_response(stream: &mut TcpStream) -> Result<String, CliError> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 512];
    while !data.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream
            .read(&mut buffer)
            .map_err(|source| CliError::Transport(format!("read websocket handshake: {source}")))?;
        if count == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..count]);
        if data.len() > 65_536 {
            return Err(CliError::Transport(
                "websocket handshake exceeded 64 KiB".to_owned(),
            ));
        }
    }
    Ok(String::from_utf8_lossy(&data).to_string())
}

fn read_exact(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, String> {
    let mut data = vec![0_u8; len];
    stream
        .read_exact(&mut data)
        .map_err(|source| format!("read websocket frame: {source:?}"))?;
    Ok(data)
}

fn websocket_mask() -> [u8; 4] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    nanos.to_ne_bytes()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use rusty_manifold_model::{
        DottedId, ManifoldSampleQuality, ManifoldScalarF32Sample, SchemaId,
    };

    use super::*;

    #[test]
    fn publishes_scalar_samples_to_loopback_broker() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback broker");
        let port = listener.local_addr().expect("broker address").port();
        let (command_tx, command_rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept publisher");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("set write timeout");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /manifold/v1/events HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: loopback-test\r\n\r\n",
                )
                .expect("write handshake");

            for _ in 0..2 {
                let command = read_client_text_frame(&mut stream);
                command_tx.send(command).expect("publish command text");
                write_server_text_frame(
                    &mut stream,
                    r#"{"type":"command_ack","accepted":true,"status":"published"}"#,
                );
            }
        });

        let config = SyntheticScalarPublishConfig {
            broker_host: "127.0.0.1".to_owned(),
            broker_port: port,
            broker_path: "/manifold/v1/events".to_owned(),
            sample_interval: Some(Duration::ZERO),
        };
        let report = publish_synthetic_scalar_samples(&config, &samples()).expect("publish");

        assert_eq!(report.sample_count, 2);
        assert_eq!(report.accepted_count, 2);
        assert_eq!(report.published_count, 2);
        for sequence_id in 0..2 {
            let command = command_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("receive broker command");
            assert!(command.contains("\"command\":\"publish_stream_event\""));
            assert!(command.contains("\"stream\":\"stream.synthetic_wave\""));
            assert!(command.contains(&format!("\"sequence_id\":{sequence_id}")));
            assert!(command.contains("\"$schema\":\"rusty.manifold.sample.scalar_f32.v1\""));
        }
    }

    fn samples() -> Vec<ManifoldScalarF32Sample> {
        (0..2)
            .map(|sequence_id| ManifoldScalarF32Sample {
                schema_id: SchemaId::new("rusty.manifold.sample.scalar_f32.v1").expect("schema"),
                stream_id: DottedId::new("stream.synthetic_wave").expect("stream id"),
                source_module_id: DottedId::new("module.synthetic_wave_provider")
                    .expect("module id"),
                sequence_id,
                timestamp_domain: DottedId::new("clock.host_monotonic").expect("clock id"),
                timestamp_ms: 1000 + sequence_id,
                value: 0.5,
                value01: 0.5,
                units: "normalized".to_owned(),
                quality: ManifoldSampleQuality::Synthetic,
            })
            .collect()
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0_u8; 256];
        while !data.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).expect("read HTTP request");
            assert_ne!(count, 0, "publisher closed before request completed");
            data.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8_lossy(&data).to_string()
    }

    fn read_client_text_frame(stream: &mut TcpStream) -> String {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).expect("read frame header");
        assert_eq!(header[0] & 0x0F, 0x1);
        assert_ne!(header[1] & 0x80, 0, "client frames must be masked");
        let mut length = (header[1] & 0x7F) as usize;
        if length == 126 {
            let mut extended = [0_u8; 2];
            stream.read_exact(&mut extended).expect("read u16 length");
            length = u16::from_be_bytes(extended) as usize;
        } else if length == 127 {
            let mut extended = [0_u8; 8];
            stream.read_exact(&mut extended).expect("read u64 length");
            length = u64::from_be_bytes(extended) as usize;
        }
        let mut mask = [0_u8; 4];
        stream.read_exact(&mut mask).expect("read mask");
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).expect("read payload");
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        String::from_utf8(payload).expect("frame payload is UTF-8")
    }

    fn write_server_text_frame(stream: &mut TcpStream, text: &str) {
        let payload = text.as_bytes();
        let mut header = Vec::new();
        header.push(0x81);
        if payload.len() < 126 {
            header.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        stream.write_all(&header).expect("write frame header");
        stream.write_all(payload).expect("write frame payload");
    }
}
