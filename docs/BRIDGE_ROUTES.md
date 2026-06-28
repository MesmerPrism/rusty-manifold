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
| Volatile low-rate values | `telemetry` + UDP/OSC + best effort | Staleness and packet loss are expected adapter concerns. |
| Device management | `device_management` + ADB/platform tooling + transport acknowledged | Proves host/device operation only; not runtime adoption. |
| High-rate media | `media_payload` + `media_data` + media data plane | Frames stay out of command JSON. |
| Diagnostics and pull artifacts | `artifact_evidence` + file/platform tooling + artifact captured | Requires manifests, refs, hashes, or scorecards downstream. |

## Fixtures

Current valid fixtures:

- `fixtures/bridge-route/command-websocket-applied-route.json`
- `fixtures/bridge-route/command-websocket-applied-evidence.json`
- `fixtures/bridge-route/marker-lsl-timestamped-route.json`
- `fixtures/bridge-route/telemetry-udp-best-effort-route.json`
- `fixtures/bridge-route/device-adb-transport-route.json`
- `fixtures/bridge-route/media-h264-data-plane-route.json`

Damaged fixture:

- `fixtures/damaged/bridge-route-command-transport-only-evidence.json`

The damaged fixture proves that a command route requiring runtime acceptance
and applied evidence rejects a summary that only contains sent,
transport-acknowledged, and authority-accepted stages.

## Non-Scope

This contract does not start a broker, open a socket, publish LSL, send UDP,
call ADB, stage files, decode video, render frames, launch apps, or inspect a
Quest headset. Those belong in adapters and downstream product repos.
