# Rusty Manifold Agent Notes

This is the clean source repository for Rusty Manifold. Keep committed content
self-contained and free of local planning paths, private source references,
private package names, and historical naming drift.

## Purpose

Rusty Manifold owns typed contracts for graph, stream, command, lease, module,
host, clock, session, package, and audit surfaces. It should remain usable
without UI frameworks, platform SDKs, runtime sockets, device APIs, media
libraries, or external workflow tools.

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

## Naming

- Public type names use `Manifold*`.
- Schema IDs use `rusty.manifold.<family>.<name>.v<major>`.
- Stable ids use lowercase dotted identifiers. Segments start and end with an
  ASCII lowercase letter or digit; `_` and `-` are allowed inside a segment.
- Prefer behavior-oriented ids such as `stream.wave`, `clock.host_monotonic`,
  `module.synthetic_provider`, and `transport.loopback`.

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
