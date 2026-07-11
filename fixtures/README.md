# Fixtures

The `peer/` and `peer-review/` fixtures cover Manifold-owned peer identity,
status proposals, accepted state, decisions, rejections, audit events, and
application receipts. Matching damaged fixtures prove stale authority/status,
replay, untrusted identity, role escalation, high-rate payload, and advisory
command rejection.

The `runtime-host/` fixtures prove snapshot/restart parity, command dispatch
and application receipts, explicit lease expiry, and audit persistence. Damaged
runtime-host requests cover unknown commands and missing/expired leases.

The `broker-product/` matrix covers the camera-free base, independent camera,
direct-P2P, and BLE profiles, exactly-one standalone/embedded mode, committed
lock parity, stale specs, and union-permission rejection.

Fixtures are committed contract examples. They should be small, deterministic,
and safe to use in tests, generated schemas, documentation, and clients.

## Layout

- `host/`: host manifest examples.
- `module/`: module manifest and runtime-state examples.
- `stream/`: stream registry examples.
- `synthetic/`: deterministic synthetic scalar source profiles and generated
  JSONL sample fixtures.
- `stream-subscription/`: stream subscription request, renewal, release, accepted, and rejection examples.
- `command/`: command and lease request, renewal, release, acknowledgement,
  rejection, and remote-camera command handoff examples.
- `authority/`: command authority snapshots tying host, clock, stream registry, module runtime, command ids, and leases together, including the remote-camera Q2Q session authority snapshot.
- `audit/`: authority audit-event examples.
- `authority-review/`: deterministic command authority review outputs from the fixture CLI, including the remote-camera Q2Q receiver, sender, status, and stop reviews.
- `command-dispatch/`: deterministic source-only command dispatch receipt outputs from the fixture CLI, including the remote-camera Q2Q receiver-first handoff receipts.
- `coordination/`: deterministic coordination session plans, message logs,
  and scorecards for Quest-to-Quest LAN, Quest-to-phone LAN, and remote relay
  two-way streaming.
- `lease-review/`: deterministic lease authority review outputs from the fixture CLI.
- `lease-release-review/`: deterministic lease release authority review outputs from the fixture CLI.
- `lease-renewal-review/`: deterministic lease renewal authority review outputs from the fixture CLI.
- `stream-registry-review/`: deterministic stream-registry authority review outputs from the fixture CLI.
- `stream-subscription-review/`: deterministic stream-subscription authority review outputs from the fixture CLI.
- `stream-subscription-release-review/`: deterministic stream-subscription release authority review outputs from the fixture CLI.
- `stream-subscription-renewal-review/`: deterministic stream-subscription renewal authority review outputs from the fixture CLI.
- `authority-expiry/`: authority expiry-sweep request and rejection examples.
- `authority-expiry-review/`: deterministic authority expiry-sweep review outputs from the fixture CLI.
- `authority-application/`: deterministic accepted-state application outputs from the fixture CLI.
- `module-runtime-review/`: deterministic module runtime-state authority review outputs from the fixture CLI.
- `host-manifest-review/`: deterministic host manifest authority review outputs from the fixture CLI.
- `clock-review/`: deterministic clock snapshot authority review outputs from the fixture CLI.
- `graph/`: static graph manifest examples.
- `package/`: package manifest examples.
- `deployment/`: deployment manifest examples.
- `clock/`: clock snapshot examples.
- `validation/`: scorecard examples.
- `host-run/`: install, launch, validation-slot, command, and run-evidence examples for generic host shells.
- `bridge-route/`: transport-neutral bridge route descriptors and evidence
  summaries for command, marker, telemetry, device-management, and media
  data-plane routes.
- `broker-adapter/`: deterministic standalone/embedded configs, product locks,
  and applied/unknown/unleased receipts. Paired receipts deliberately differ in
  placement and lock fingerprint while preserving byte-equivalent Runtime Host
  dispatch/application decisions and `module.runtime.host` authority ownership.
- `admission/`: deterministic grant/token lifecycle from issue through one-time
  use, replay rejection, explicit revocation, and post-revocation rejection,
  plus damaged signing-fingerprint and capability-escalation requests. The
  signing hashes are synthetic fixture values, never production identities.
- `shell-handoff/`: contract-backed shell handoff and Manifold review receipt examples for downstream operator or render shells.
- `simulator/`: deterministic source-only simulator snapshots.
- `damaged/`: intentionally invalid examples.

Damaged fixtures are as important as valid fixtures because they prove clients
and validators reject unsafe or ambiguous state.
