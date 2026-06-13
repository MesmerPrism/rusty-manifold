# Coordination Sessions

Coordination sessions are Manifold's source-only utility for multi-endpoint
stream timing. They describe who participates, which low-rate transports carry
control or advisory status, which receiver-first gates must pass, and what
scorecard proves the ordering.

This utility does not start cameras, open sockets, forward relay traffic,
decode H.264, run ADB, or execute platform commands. Runtime adapters consume
accepted plans and scorecards later.

## Why This Exists

The legacy Quest-to-Quest work used two agents connected through the headset
route to exchange low-rate readiness messages before starting camera streams.
That made the timing tractable: arm receivers first, announce receiver
readiness, then authorize sender start. The same lesson applies to
Quest-to-phone and remote relay routes, but the authority boundary needs to be
generic and reusable.

Manifold now captures that pattern as:

- `ManifoldCoordinationSessionPlan`: participants, transports, inboxes,
  gates, command refs, media stream refs, and safety policy.
- `ManifoldCoordinationMessageLog`: the observed low-rate coordination
  messages in order.
- `ManifoldCoordinationScorecard`: deterministic evidence that the plan was
  followed without runtime execution.

The committed fixtures cover:

- same-network Quest-to-Quest LAN streaming;
- same-network Quest-to-Android-phone LAN streaming;
- remote relay mediated two-way Quest streaming.

The remote-camera stream refs intentionally name camera `50` and camera `51`
as the outside left/right camera feeds used by the downstream headset camera
adapter.

## Adapter Boundaries

Manifold owns the plan, message log, gate evaluation, rejection codes, and
scorecard. It only sees low-rate metadata, artifact refs, and command ids.

Rusty Quest owns headset platform details: permissions, camera discovery,
camera 50/51 mapping, session lifecycle, and OpenXR/Android/Horizon adapter
work.

Android phone or Termux companion adapters own phone-local transport setup,
service lifecycle, and local network discovery. Peer mesh work can feed
`coordination.message.peer_gossip_status`, but it remains advisory status.
Peer mesh must not authorize commands, satisfy sender-start gates, proxy ADB,
or carry media payloads.

Relay adapters own remote relay credentials, connectivity, NAT traversal,
store-and-forward behavior, and media-plane routing. Relay status can satisfy
advisory gates, but sender start still requires Manifold's receiver-readiness
gates and command authorization.

Media payloads stay out of coordination JSON. H.264 frames, textures, camera
buffers, and high-rate samples must use data/media-plane transports described
by Manifold metadata.

## CLI

Generate or check a deterministic scorecard:

```powershell
cargo run -p rusty-manifold-fixtures -- simulate-coordination --plan fixtures/coordination/remote-camera-q2q-lan-plan.json --messages fixtures/coordination/remote-camera-q2q-lan-messages.json
cargo run -p rusty-manifold-fixtures -- simulate-coordination --plan fixtures/coordination/remote-camera-q2q-lan-plan.json --messages fixtures/coordination/remote-camera-q2q-lan-messages.json --check --expected fixtures/coordination/remote-camera-q2q-lan-scorecard.json
```

The validator also checks all valid and damaged coordination fixtures:

```powershell
cargo run -p rusty-manifold-fixtures -- validate
```

Damaged fixtures currently prove three required safety properties:

- sender start before receiver readiness is rejected;
- advisory peer or relay status cannot authorize commands;
- high-rate or inline media payloads in coordination messages are rejected.
