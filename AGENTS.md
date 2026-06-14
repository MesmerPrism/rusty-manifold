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
6. `docs/IMPLEMENTATION_PLAN.md`
7. `docs/MODULE_PACKAGE_STRATEGY.md`
8. `docs/SCHEMA_EVOLUTION.md`
9. `fixtures/README.md`

## Architecture Rules

- Manifold authority owns accepted mutable state, revisions, leases, command
  decisions, lifecycle records, registries, clocks, session evidence, and audit.
- Clients observe or request through typed contracts. They do not mutate
  accepted state directly.
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
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-schema -- export --check
```

When schema tooling exists, add deterministic schema export and fixture
validation checks to this list.
