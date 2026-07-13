# Rusty Manifold Agent Notes

This is the clean source repository for Rusty Manifold. Keep committed content
self-contained and free of local planning paths, private source references,
private package names, and historical naming drift.

Rusty Morphospace is the top-level project/platform umbrella. This repo remains
the Manifold lane inside that umbrella: morphology of regulation, command
authority, graph plumbing, streams, leases, modules, clocks, transports, and
audit. Do not introduce `rusty.morphospace.*` schemas here; use
`rusty.manifold.*` for Manifold contracts.

Project-owned source in this repo is licensed `AGPL-3.0-or-later`. Keep
third-party dependencies, generated artifacts, fixtures imported from other
projects, binary releases, and external tools under their own provenance and
notice requirements; see `docs/LICENSING.md`.

## Purpose

Rusty Manifold owns typed contracts for graph, stream, command, lease, module,
host, clock, session, package, and audit surfaces. It should remain usable
without UI frameworks, platform SDKs, runtime sockets, device APIs, media
libraries, or external workflow tools.

Makepad dependencies belong only in downstream app-shell/UI lanes such as
Hostess Makepad shells, Studio Makepad/UI shells, and public Rusty XR Makepad
examples. This repo stays Makepad-free.

Rusty Lattice owns situated relation contracts: reference spaces, transforms,
tracked poses, view sets, spatial input roles, frame-state binding,
calibration, validity, confidence, and runtime capability snapshots. Manifold
may route, authorize, lease, subscribe to, or audit Lattice observations, but
it must not define Lattice relation semantics or default to legacy
`rusty.xr.*` names for new command/session/stream work.

## Read Order

1. `README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/GLOSSARY.md`
4. `docs/PORTS_AND_ADAPTERS.md`
5. `docs/COMMANDS_LEASES_AND_AUTHORITY.md`
6. `docs/PEER_IDENTITY_AND_STATUS_AUTHORITY.md`
7. `docs/PEER_SESSION_AUTHORITY.md`
8. `docs/PEER_MESH_AUTHORITY.md`
9. `docs/PEER_RUNTIME_HOST.md`
10. `docs/MEDIA_SESSION_AUTHORITY.md`
11. `docs/RUNTIME_HOST.md`
12. `docs/BROKER_PRODUCTS.md`
13. `docs/BROKER_ADAPTERS.md`
14. `docs/ADMISSION.md`
15. `docs/IMPLEMENTATION_PLAN.md`
16. `docs/MODULE_PACKAGE_STRATEGY.md`
17. `docs/SCHEMA_EVOLUTION.md`
18. `fixtures/README.md`

## Architecture Rules

- Manifold authority owns accepted mutable state, revisions, leases, command
  decisions, lifecycle records, registries, clocks, session evidence, and audit.
- Clients observe or request through typed contracts. They do not mutate
  accepted state directly.
- Peer adapters propose stable identity and bounded low-rate status through
  `rusty-manifold-peer`; only Manifold review/application advances accepted
  peer state or emits the authoritative audit/application receipt.
- Authenticated rendezvous adapters may propose expiring peer sessions, but
  Manifold alone accepts/rejects them, advances the session revision, revokes
  them, and emits revision-scoped topology authorization. Platform topology
  must not start from adapter evidence alone.
- N-peer adapters may propose unique sorted membership and bounded routes, but
  Manifold owns mesh revision, deterministic coordinator, route ranking,
  split-brain rejection, expiry, revocation, direct-lane eligibility, and
  audit. Advisory gossip is never direct-route or media authority.
- Products opt into `rusty-manifold-peer-runtime-host` at compile time when
  they need one restartable owner for accepted peer status, enrollment,
  signed rendezvous, session/mesh, signed topology, direct-lane lease, replay,
  and audit state. The extension calls the pure peer authorities and must not
  absorb Android, Termux, sidecar, socket, codec, or media-payload behavior.
- Generic media-session descriptors bind accepted Manifold session/stream
  state to source, processor, route, sink, and platform runtime references.
  They carry no media bytes or app-specific capture/codec/socket policy;
  platform lifecycle receipts remain downstream adoption evidence.
- Packaged media products use `rusty-manifold-media-session` to retain the
  exact typed descriptor, strict sorted reference sets, and canonical SHA-256.
  This binding authorizes only the referenced adoption action: command
  acceptance is never proof that Java, Android, a codec, a socket, a source, or
  a sink completed its effect.
- Media authority provenance keeps five identities distinct: the broker
  product lock id plus semantic fingerprint, SHA-256 of exact packaged product
  lock bytes, packaged broker client-lock id/SHA-256, signature-projected
  client/admission grant, and app feature-lock id/SHA-256. Never project a
  client-lock digest into an app feature-lock field; equal or mismatched lock
  bindings must fail closed before an inner media lease is minted.
- Standalone and embedded products must use `rusty-manifold-runtime-host` for
  revisioned review/application, lease expiry, restart, replay, and audit. The
  host is source-only; product adapters and policy stay outside it.
- Broker product features resolve through `rusty-manifold-broker-product` into
  exact commands, streams, modules, permissions, and fingerprint. Generic
  `media_session` is camera-free; `camera_media` explicitly layers capture
  authority over it. Downstream manifests project the lock and must not expand
  it.
- `spec_fingerprint` is the deterministic semantic closure fingerprint. It is
  not the exact packaged-file hash. Broker adapter configs and receipts carry
  separately named `product_lock_sha256` evidence for the accepted bytes.
- `rusty-manifold-broker-adapter` is the only standalone/embedded command
  adoption path. Placement changes adapter role labels, never acceptance rules:
  both modes bind the exact product lock, derive the same Runtime Host command
  registry and lease policy, preserve host receipts, and name
  `module.runtime.host` as authority. Java/JNI/process layers remain adapters.
- `ManifoldBrokerRuntime` is the only product mutation gate. It co-locates the
  exact broker adapter with Manifold admission, retains one-use permits bound
  to their opaque token, packaged client-lock id/SHA-256,
  signature-projected client, exact command capability,
  use-creation admission revision, expiry, and provider epoch, consumes a permit before one
  Runtime Host review/apply attempt, and emits the combined receipt. Rebinds to
  the same live provider preserve state; a provider restart creates a fresh
  explicit epoch. An unrelated grant/token mutation may advance the global
  admission revision without invalidating another client's bounded use;
  revocation or expiry invalidates only uses derived from the affected token.
- Runtime Host requests that carry low-rate effect parameters must bind the
  canonical typed payload through
  `rusty.manifold.runtime_host.typed_params_digest.v1`. Review, dispatch, and
  application receipts preserve that exact digest; mismatched, malformed, or
  over-4096-byte canonical payload bindings reject before accepted state moves.
- `rusty-manifold-admission` owns trusted client grants, opaque 256-bit
  short-lived tokens, one-time capability-use request ids, explicit revocation
  and expiry, accepted revisions, and audit. Platform adapters may prove UID,
  package, and signing certificate, but they must pass the exact projected
  identity to Manifold and may not widen capabilities or mint tokens locally.
- When CLI, API, GUI, bridge, or platform helpers can request the same state
  change, they must all map into one Manifold command/schema/review path.
  Helper-local readback or UI state is observation evidence only until the
  Manifold acceptance/rejection receipt records the result.
- Every mutating GUI action must have a CLI route that calls the same command
  implementation. Agents validate behavior through CLI/command outputs; humans
  judge usability, layout, focus, and interaction quality.
- Keep control, discovery, data descriptors, render adoption, and feedback
  separate when a route involves streams or media.
- Keep high-rate packets, frames, buffers, textures, audio, and sensor payloads
  outside low-rate JSON command surfaces.
- Add descriptors, fixtures, and damaged-input expectations before runtime
  loaders, transports, or sidecars.
- Put platform SDKs, media stacks, device APIs, UI frameworks, and optional
  transports in adapter crates or downstream products.
- Do not add Makepad as a dependency, feature, fixture requirement, schema
  owner, or validation prerequisite.

## Naming

- Public type names use `Manifold*`.
- Schema IDs use `rusty.manifold.<family>.<name>.v<major>`.
- Stable ids use lowercase dotted identifiers. Segments start and end with an
  ASCII lowercase letter or digit; `_` and `-` are allowed inside a segment.
- Prefer behavior-oriented ids such as `stream.wave`, `clock.host_monotonic`,
  `module.synthetic_provider`, and `transport.loopback`.

## Sustainable Design Guardrails

- Treat monolithic file pressure as an ownership problem, not a line-count
  problem. Split only by durable authority, schema, route, validation, adapter,
  or test-family boundaries; preserve facades, schema IDs, serde fields,
  fixture outputs, CLI behavior, validation outcomes, and dependency boundaries.
- After a split, update the nearest distributed file map: this `AGENTS.md`,
  `README.md`, `docs/ARCHITECTURE.md`, fixture docs, validation docs, or the
  planning `agent-state\iteration-events.jsonl`.
- Keep `AGENTS.md`, README, and skill files as concise routing indexes. Move
  lane-specific recipes, device/build detail, compatibility ledgers, and long
  validation flows into named docs or runbooks.
- Keep legacy Rusty-XR names as explicit compatibility surfaces only. New
  schemas, routes, and types use the owning lane (`rusty.manifold.*`,
  `rusty.lattice.*`, `rusty.matter.*`, `rusty.optics.*`, `rusty.quest.*`, or
  repo-local names); do not introduce `rusty.morphospace.*` schemas or
  `Morphospace*` core types by default.
## Validation

Run the narrow checks before committing:

```powershell
cargo fmt --all --check
cargo test --workspace
cargo test -p rusty-manifold-peer-runtime-host
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-schema -- export --check
```

When schema tooling exists, add deterministic schema export and fixture
validation checks to this list.
