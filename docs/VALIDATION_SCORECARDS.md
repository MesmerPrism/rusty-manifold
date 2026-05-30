# Validation Scorecards

Validation evidence should be structured enough for tools, dashboards, and
agents to inspect without log scraping.

## Validation Ladder

1. Schema round-trip and deterministic export.
2. Synthetic fixtures and damaged-input fixtures.
3. Source-only topology simulator.
4. Command path with machine-readable acknowledgement and rejection.
5. Read-only UI or dashboard rendering from fixtures.
6. Bounded live host smoke.
7. Route or media scorecard before performance claims.

## Scorecard Fields

Scorecards should record ids, revisions, selected backend, fallback reason,
queue bounds, packet/frame counts, timestamp domains, correlation quality,
timing windows, drop/reuse/adoption counts, and issue codes.
