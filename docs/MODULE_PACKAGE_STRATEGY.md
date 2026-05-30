# Module Package Strategy

Manifold modules should be distributed as packages, not as hard-coded runtime
features.

## Decision

Keep `rusty-manifold` focused on contracts, fixtures, validators, schemas, and
small model helpers. Put first-party modules in a separate curated module
package workspace once the package and module manifests are stable.

## Package Classes

- `provider`: acquires or generates source streams.
- `processor`: derives new streams from input streams.
- `sink`: records, exports, or forwards streams.
- `bridge`: maps Manifold streams or commands to an external protocol.
- `control_adapter`: exposes bounded control integrations.
- `diagnostic`: reports health, timing, validation, or evidence.
- `supervisor`: watches lifecycle, recovery, or policy state.

## Provider Versus Processor

A provider owns communication with a source. Examples:

- hardware sensor acquisition;
- platform API subscription;
- file or replay source;
- synthetic generator.

A processor owns signal transformation. Examples:

- breathing volume approximation from accelerometer samples;
- beat-window metrics from RR intervals;
- coherence or entropy features;
- smoothing, resampling, gating, calibration, or quality scoring.

Provider modules should decode payloads into direct, timestamped streams.
Processor modules should consume those streams and publish derived streams with
their own settings, calibration state, quality, and confidence.

## Multi-Backend Package Shape

A package may contain one stable Manifold-facing module with multiple platform
backends:

```text
packages/<package-id>/
  manifests/
    package.manifold.json
    modules/
    streams/
    commands/
  fixtures/
    valid/
    damaged/
  crates/
    model/
    provider/
    processor/
    backend-desktop/
    backend-mobile/
    backend-synthetic/
```

The Manifold-facing ids stay stable across backends. Backend ids describe how a
host can provide that behavior on a specific platform.

## First Sensor Package Shape

A first biosignal sensor package should use this split:

- `module.biosignal_sensor.provider`: provider module with platform backends.
- `stream.biosignal.hr`: direct heart-rate stream.
- `stream.biosignal.beat_interval`: direct beat interval stream.
- `stream.biosignal.waveform`: direct waveform stream when enabled.
- `stream.motion.accelerometer`: direct accelerometer stream when enabled.
- `stream.device.status`: device status and battery stream.
- `processor.breath.volume_from_acc`: processor module consuming accelerometer.
- `processor.beat.hrv_window`: processor module consuming beat intervals.
- `processor.beat.coherence`: processor module consuming beat intervals.
- `processor.breath.dynamics`: processor module consuming a calibrated breath
  waveform.

If a device-specific name is needed, it belongs in the package metadata and
backend evidence. Generic stream families should stay stable enough for other
sensors to reuse.

## Availability Flow

1. Package catalog declares possible modules.
2. Host manifest declares supported backends, permissions, and missing
   requirements.
3. Deployment manifest selects a module/backend/host combination.
4. Runtime state reports lifecycle and selected backend.
5. Stream registry reports active streams.
6. Scorecards report timing, drops, malformed frames, backend fallbacks, and
   rejection reasons.

## Split Rules

Keep first-party packages in one curated repo until one of these is true:

- licensing differs materially from the main package workspace;
- the package carries large native binaries or model assets;
- platform signing or app-store obligations dominate the release;
- the module has private behavior or private datasets;
- the release cadence must decouple from other first-party packages;
- the package needs a dedicated public issue/release/documentation surface.

Until then, one curated package workspace is easier to validate and govern than
one repository per module.
