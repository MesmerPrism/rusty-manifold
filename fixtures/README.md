# Fixtures

Fixtures are committed contract examples. They should be small, deterministic,
and safe to use in tests, generated schemas, documentation, and clients.

## Layout

- `host/`: host manifest examples.
- `module/`: module manifest and runtime-state examples.
- `stream/`: stream registry examples.
- `command/`: command and lease examples.
- `graph/`: static graph manifest examples.
- `package/`: package manifest examples.
- `deployment/`: deployment manifest examples.
- `clock/`: clock snapshot examples.
- `validation/`: scorecard examples.
- `simulator/`: deterministic source-only simulator snapshots.
- `damaged/`: intentionally invalid examples.

Damaged fixtures are as important as valid fixtures because they prove clients
and validators reject unsafe or ambiguous state.
