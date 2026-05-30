# Implementation Plan

Rusty Manifold should be built in slices that make module availability,
platform hosts, and processing graphs explicit before any device-specific
runtime code appears.

## Slice 1: Contract Spine

Goal: make all later modules describe themselves without platform code.

Deliverables:

- `ManifoldPackageManifest`
- `ManifoldModuleManifest`
- `ManifoldModuleRuntimeState`
- `ManifoldStreamManifest`
- `ManifoldStreamRegistrySnapshot`
- `ManifoldCommandDescriptor`
- `ManifoldCommandEnvelope`
- `ManifoldCommandAck`
- `ManifoldCommandRejection`
- `ManifoldControlLease`
- `ManifoldHostManifest`
- `ManifoldDeploymentManifest`
- `ManifoldClockSnapshot`
- `ManifoldValidationScorecard`

Implementation:

- keep the existing `rusty-manifold-model` crate for shared ids, versions, and
  revisions;
- add focused model crates only when a boundary is proven by fixtures;
- add committed valid and damaged JSON fixtures for every manifest family;
- add deterministic fixture validation before schema export;
- add schema export after the model names stabilize.

Validation:

```powershell
cargo fmt --all --check
cargo test --workspace
```

Later validation slots:

```powershell
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-schema -- export --check
```

## Slice 2: Module Availability Model

Goal: answer "what modules can this host run?" without loading dynamic code.

Deliverables:

- package catalog document;
- module manifest document;
- host manifest document;
- deployment selection document;
- runtime-state snapshot document;
- stream registry snapshot document.

Rules:

- package manifests declare what a package can provide;
- host manifests declare what this host can actually run now;
- deployment manifests select a package, module, backend, and host;
- runtime state reports lifecycle, active backend, streams, health, and issues;
- stream registry snapshots show accepted live streams at one revision.

No dynamic plugin loading is needed in this slice.

## Slice 3: Source-Only Simulator

Goal: prove graph, host, module, command, lease, and stream contracts without
Bluetooth, sockets, UI, or platform SDKs.

Deliverables:

- synthetic host fixture;
- synthetic provider module fixture;
- synthetic processor module fixture;
- synthetic graph fixture connecting provider to processor;
- command acceptance and rejection fixtures;
- runtime-state transition fixtures;
- stream registry diff fixture.

The simulator may be a test helper or CLI. It should produce the same manifest
and runtime-state shapes that a live host will produce later.

## Slice 4: Platform Host Contracts

Goal: support Windows, Android phone, and Android headset hosts through the
same Manifold contracts.

Host categories:

- `desktop.windows`: desktop host with platform-specific device and process
  APIs.
- `android.phone`: Android phone host with app-owned permissions and services.
- `android.headset`: Android headset host with app-owned permissions,
  lifecycle, and foreground constraints.

Rules:

- Manifold core does not link platform SDKs.
- Platform code lives in host products, adapter crates, or module package
  repos.
- Host manifests declare permissions, transport routes, device APIs, lifecycle
  limits, and selected backend evidence.
- A platform host can advertise a module package only when the required
  permissions and backend dependencies are present.

## Slice 5: First-Party Module Package Workspace

Goal: provide curated modules without turning `rusty-manifold` into a module
dump.

Create a separate workspace after slices 1-4 are stable:

```text
rusty-manifold-packages/
  packages/
    synthetic/
    polar-h10/
    recorder/
    bridge-osc/
    bridge-lsl/
  crates/
    module-host-testkit/
```

This should be one repo for first-party curated packages at first. Split a
package into its own repo only when it has unusual licensing, large native
payloads, a separate release cadence, private behavior, or heavy platform
obligations.

## Slice 6: First Sensor Package

The first real sensor package should be a multi-stream biosignal provider with
parallel platform backends and separate processors.

Provider responsibilities:

- scan, connect, configure, stream, stop, disconnect;
- expose stream descriptors for heart-rate, beat interval, waveform,
  accelerometer, device status, and backend health data where supported;
- report single-owner constraints for raw high-rate streams;
- preserve both sensor timestamps and host receive timestamps;
- expose command rejections for permission, device busy, unsupported stream,
  backend missing, timeout, and malformed frame.

Processor responsibilities:

- consume accepted streams;
- produce derived streams;
- declare calibration, warmup, quality, confidence, and reset commands;
- stay testable from recorded or synthetic fixtures.

Do not put processor behavior inside the provider unless the value is a direct
decode of the device payload.

## Slice 7: Runtime Host

Only after the above slices:

- implement a local in-process runtime host;
- add typed client APIs;
- add optional HTTP, CLI, or MCP adapters;
- add live platform smoke tests in downstream host repos.

The first runtime host should still be able to run synthetic packages without
platform SDKs or hardware.
