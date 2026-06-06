# Modules

Manifold modules are declared runtime capabilities.

## Module Kinds

- `provider`: produces streams or metadata.
- `processor`: consumes streams and produces derived streams.
- `sink`: records, exports, or forwards streams.
- `bridge`: maps Manifold surfaces to an external protocol.
- `control_adapter`: exposes bounded command integrations.
- `diagnostic`: reports health, timing, validation, or evidence.
- `supervisor`: watches lifecycle, recovery, or policy state.

## Manifest Fields

A module manifest should be able to describe:

- stable module id, kind, label, version, and lifecycle states;
- provided streams, consumed streams, accepted commands, and services;
- permissions, external tools, platform support, and resource locks;
- timestamp behavior and clock-correlation policy;
- sensitivity, retention, UI subscription policy, and chart policy;
- health metrics, failure policy, issue codes, and fallback chain.

## Runtime State

Runtime state is accepted by Manifold authority as contract state. A module,
host shell, UI, or tool may propose a `ManifoldModuleRuntimeStateChangeRequest`,
but the source-only reviewer decides whether the proposed state matches the
authority revision, module lease, review clock, runtime revision, selected
backend, streams, commands, and lifecycle invariants. A module lease that has
expired at the review clock is rejected even if it is still present in
accepted authority state.

Accepted reviews return the new `ManifoldModuleRuntimeState` plus a computed
`ManifoldModuleRuntimeTransition`. Rejected reviews return a
machine-readable `ManifoldModuleRuntimeStateRejection`. Neither path starts a
process, loads dynamic code, opens transports, or calls platform lifecycle APIs.

## Runtime State Application

Accepted runtime-state reviews become accepted authority state only through a
`ManifoldModuleRuntimeStateAuthorityApplication` receipt. The receipt advances
the authority revision and replaces the reviewed module runtime state in the
snapshot. Rejected reviews produce a
`ManifoldAuthoritySnapshotApplicationRejection` and leave accepted state
unchanged.

Application is still source-only. It does not start, stop, load, unload,
signal, or contact a runtime module.
