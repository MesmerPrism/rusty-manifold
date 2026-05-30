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
- Stream registry and topology fixtures.
- Clock domain and correlation vocabulary.
- Validation scorecards and damaged-input fixtures.
- Supply-chain and provenance fields for packages and adapters.

## Non-Scope

- Runtime daemons or sockets.
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

## First Validation

```powershell
cargo fmt --all --check
cargo test --workspace
```
