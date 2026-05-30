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
