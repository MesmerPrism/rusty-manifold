# Bridge Routes

Bridge routes classify how a downstream adapter moves commands, telemetry,
settings, media, or evidence between hosts and apps. They are contract
descriptors, not transport implementations.

## Decision

Start with static route descriptors and evidence summaries. Manifold owns the
route vocabulary and required evidence stages; adapters own WebSocket, UDP,
OSC, LSL, ADB, file staging, platform tooling, and media data-plane execution.

## Route Fields

`ManifoldBridgeRouteDescriptor` records:

- route intent: command, runtime settings, marker, telemetry, device
  management, media control, media payload, artifact evidence, or panel
  interaction;
- plane: control, telemetry, data, media data, render adoption, evidence, or
  feedback;
- transport family: WebSocket, UDP, OSC, LSL, ADB, file, media data plane,
  platform tooling, manual, HTTP, stdio, or in-process;
- delivery semantics: best effort, ordered, transport acknowledged, authority
  reviewed, applied receipt required, or artifact captured;
- payload class and rate class;
- authority role: authority, adapter, observer, or evidence-only;
- required evidence stages before a route can be accepted.
- required conditions: environment, device, network, runtime, security, and
  dependency checks that must pass before route evidence is meaningful;
- timing policy: the RTT or clock-alignment strategy and metrics that a route
  adapter must report when collecting evidence.

## Evidence Stages

`ManifoldBridgeRouteEvidence` keeps delivery and adoption separate:

- `sent`: adapter attempted delivery;
- `transport_ok`: transport accepted or acknowledged the payload;
- `authority_accepted`: Manifold or another declared authority accepted the
  request;
- `runtime_accepted`: consuming runtime accepted the request;
- `applied`: runtime reported the value or command as applied;
- `observed`: independent observation confirmed expected state;
- `artifact_captured`: evidence artifact was produced.

Routes may also report `rejected` or `stale` stages. A route requiring
`applied_receipt_required` must require both `runtime_accepted` and `applied`.
Transport success alone is therefore not enough evidence for commands or
settings that must take effect.

## Transport Defaults

| Purpose | Default route shape | Notes |
| --- | --- | --- |
| Commands that must take effect | `command` + `control` + WebSocket + `applied_receipt_required` | Requires sent, transport, authority, runtime, and applied evidence. |
| Runtime settings or hotload | `runtime_settings` + `control` or `evidence` + file/WebSocket + applied receipt | Runtime effective-state remains outside transport readback. |
| Experiment markers | `marker` + `telemetry` + LSL + ordered | Good for timestamps and lab tooling, not command authority. |
| LSL stream bridge or clock echo | `stream_bridge` + telemetry/data + LSL + ordered | Describes stream name/type/source id, endpoint role, channel shape, discovery policy, warmup, sample thresholds, and clock policy. |
| WebSocket stream bridge | `stream_bridge` + data + WebSocket + ordered | Requires host port, firewall, subscriber, and transport echo RTT metrics. |
| UDP or OSC streams | `stream_bridge`/`telemetry` + UDP/OSC + best effort | Requires LAN/firewall/runtime checks; use parallel LSL clock echo when native RTT is not available. |
| ZeroMQ stream bridge | `stream_bridge` + data + ZeroMQ + best effort | The optional `rusty-manifold-zmq` adapter consumes the route descriptor and can emit a JSON QCL-084 report with broker-owned evidence for downstream Hostess/WPF protocol-matrix validation. |
| Bluetooth RFCOMM stream | `stream_bridge` + data + Bluetooth RFCOMM + ordered | Requires adapter enabled, pairing, channel, Android permission, and native round-trip metrics when an echo service exists. |
| BLE GATT notify stream | `stream_bridge` + telemetry + Bluetooth GATT + best effort | Requires adapter, pairing, GATT service/characteristic, permissions, and parallel LSL timing when notifications are one-way. |
| Volatile low-rate values | `telemetry` + UDP/OSC + best effort | Staleness and packet loss are expected adapter concerns. |
| Device management | `device_management` + ADB/platform tooling + transport acknowledged | Proves host/device operation only; not runtime adoption. |
| High-rate media | `media_payload` + `media_data` + media data plane | Frames stay out of command JSON. |
| Diagnostics and pull artifacts | `artifact_evidence` + file/platform tooling + artifact captured | Requires manifests, refs, hashes, or scorecards downstream. |

## Conditions And Timing

Operational transport routes must declare `required_conditions` and `timing`.
Conditions are the checklist a readiness module or operator UI can evaluate
before a run: firewall rules, network profile, same-LAN reachability, port
availability, ADB online/forward state, package and permission state, native
library availability, broker route readiness, runtime subscribers, Bluetooth
pairing, GATT services and characteristics, RFCOMM channels, and media codecs.
Each condition includes a stable check ref, issue codes, and an optional
remediation action for UI rendering.

Timing policy is also route-level and shared across protocols. A route can use
transport echo, applied receipt echo, protocol clock correction, native
round-trip echo, or a parallel LSL clock echo. When the protocol path cannot
produce clean timing by itself, the descriptor should point to
`bridge_route.clock.lsl.roundtrip_echo` so tests still report comparable RTT,
clock offset, jitter, sample loss, and queue delay where applicable.

## ZeroMQ Adapter Evidence

`rusty-manifold-zmq` is an optional adapter crate, not a core daemon. Default
builds are socket-free; the `runtime` feature enables pure-Rust ZeroMQ helper
examples. The PUB/SUB loopback example preserves human-readable output by
default and emits a Hostess-consumable JSON report when called with
`--json --source native-rust-broker`.

```powershell
cargo run -q -p rusty-manifold-zmq --example zmq_pub_sub_loopback --features runtime -- --json --source native-rust-broker --message-count 5
```

That JSON report records `evidence_tier=broker_owned`,
`authority.owner=rusty.manifold.transport`, the route id, bounded queue
counters, received sequences, and a `rusty.manifold.bridge.route_evidence.v1`
object with the required `sent`, `transport_ok`, and `observed` stages.
Downstream products may wrap that report as QCL-084 evidence; they must not
reinterpret Goofi, public Rusty-XR compatibility, or host-loopback dependency
checks as broker-owned promotion evidence.

## LSL Profiles

LSL routes carry a dedicated profile instead of app-specific names in generic
contracts. The profile records stream name/type/source id, endpoint role,
resolve policy, channel count and format, channel labels, warmup, sample
thresholds, and whether evidence uses raw sample timestamps, LSL time
correction, or round-trip offset.

Legacy Rusty XR broker and Sussex/AKD companion probes showed the useful
runtime checks to preserve: native `liblsl` availability must be reported as a
blocker rather than hidden behind fallback logging; inlets should resolve by a
declared policy instead of broad discovery; probes need warmup and bounded
sample windows; and useful latency evidence needs both echo sample timing and
clock-correction uncertainty where the runtime exposes it. Those lessons are
modeled here as neutral route fields and evidence refs, not as Sussex, Goofi,
or legacy broker authority.

## Fixtures

Current valid fixtures:

- `fixtures/bridge-route/command-websocket-applied-route.json`
- `fixtures/bridge-route/command-websocket-applied-evidence.json`
- `fixtures/bridge-route/marker-lsl-timestamped-route.json`
- `fixtures/bridge-route/stream-lsl-clock-roundtrip-route.json`
- `fixtures/bridge-route/stream-lsl-clock-roundtrip-evidence.json`
- `fixtures/bridge-route/telemetry-udp-best-effort-route.json`
- `fixtures/bridge-route/stream-websocket-ordered-route.json`
- `fixtures/bridge-route/stream-osc-udp-route.json`
- `fixtures/bridge-route/stream-bluetooth-rfcomm-route.json`
- `fixtures/bridge-route/stream-bluetooth-gatt-notify-route.json`
- `fixtures/bridge-route/device-adb-transport-route.json`
- `fixtures/bridge-route/media-h264-data-plane-route.json`
- `fixtures/bridge-route/stream-zeromq-pubsub-route.json`
- `fixtures/bridge-route/stream-zeromq-pubsub-evidence.json`

Damaged fixtures:

- `fixtures/damaged/bridge-route-command-transport-only-evidence.json`
- `fixtures/damaged/bridge-route-lsl-missing-profile.json`
- `fixtures/damaged/bridge-route-zeromq-missing-profile.json`
- `fixtures/damaged/bridge-route-missing-conditions.json`
- `fixtures/damaged/bridge-route-invalid-timing.json`

The damaged fixture proves that a command route requiring runtime acceptance
and applied evidence rejects a summary that only contains sent,
transport-acknowledged, and authority-accepted stages.

## Non-Scope

This contract does not start a broker, open a socket, publish LSL, send UDP,
call ADB, stage files, decode video, render frames, launch apps, or inspect a
Quest headset. Those belong in adapters and downstream product repos.
