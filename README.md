# Rusty Manifold

Rusty Manifold is the typed contract layer for graph, stream, command, lease,
module, host, clock, session, and audit surfaces across the Rusty stack.

This repository starts private and intentionally small. The first slice is
model, documentation, fixtures, and schema policy only. Runtime networking,
dynamic loading, platform SDKs, media stacks, application shells, and UI
frameworks belong in later adapter or product repositories after the contracts
can reject bad state.

## Initial Scope

- Stable names and identifier grammar.
- Versioned manifests and descriptors.
- Command, capability, lease, and rejection vocabulary.
- Remote camera command descriptors plus source-only authority review and
  dispatch receipt fixtures for receiver-first start receiver, start sender,
  status, and immediate stop handoff.
- Coordination-session contracts and simulator fixtures for same-network
  Quest-to-Quest, same-network Quest-to-phone, and remote relay two-way stream
  timing.
- Stream registry and topology fixtures.
- Synthetic scalar stream sample and oscillator profile fixtures for adapter
  bring-up, plus an opt-in fixture CLI publisher that can send those same
  bounded samples into an already-running Manifold broker for live validation.
- Clock domain and correlation vocabulary.
- Validation scorecards and damaged-input fixtures.
- Supply-chain and provenance fields for packages and adapters.

## Non-Scope

- Runtime daemons or sockets in the core model crates. The fixture CLI's
  explicit `publish-synthetic-scalar` command is a validation adapter, not a
  Manifold authority daemon.
- Dynamic plugin loading.
- Platform SDK dependencies.
- UI or application-shell code.
- Native media, codec, device, or transport dependencies in core crates.
- High-rate binary payloads in JSON command surfaces.

## Repository Shape

- `crates/`: Rust data-contract crates.
- `docs/`: architecture and policy documents.
- `fixtures/`: canonical valid and damaged JSON examples.
- `schemas/`: generated schemas once schema tooling exists.
- `tools/`: validation and export tooling once needed.

## Planning Entry Points

- `docs/IMPLEMENTATION_PLAN.md`
- `docs/COORDINATION_SESSIONS.md`
- `docs/MODULE_PACKAGE_STRATEGY.md`
- `docs/MODULES.md`
- `docs/HOSTS_AND_DEPLOYMENT.md`

## First Validation

```powershell
cargo fmt --all --check
cargo test --workspace
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-fixtures -- emit-synthetic-scalar --check --expected fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl
cargo run -p rusty-manifold-schema -- export --check
```

To drive an already-running local broker with the same synthetic stream shape:

```powershell
cargo run -p rusty-manifold-fixtures -- publish-synthetic-scalar --broker-host 127.0.0.1 --broker-port 8765 --sample-count 40
```
