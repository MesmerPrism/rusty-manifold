# Clock And Timebase

Manifold records clock domains and correlations. It does not replace platform
clocks.

## Rules

- Use monotonic elapsed time as the canonical ordering source per host.
- Record wall-clock time as a human and export label.
- Keep source, receive, accept, media, render, relay, and sidecar domains
  explicit.
- Include clock epoch id, sequence number, read uncertainty, health, and
  wall-clock adjustment counters.
- Represent correlations as windows with offset, drift, jitter, uncertainty,
  quality, and discontinuity reason.

Stream events should carry both source timestamps and Manifold receive or
accept timestamps with named domains.

## Authority Application

Clock snapshot changes are reviewed before accepted state changes. The
source-only reviewer requires a valid clock lease and rejects that lease if it
has expired at the review clock. Accepted reviews are applied through
`ManifoldClockSnapshotAuthorityApplication`, which advances only the authority
revision and accepted clock snapshot. Rejected reviews produce a
`ManifoldAuthoritySnapshotApplicationRejection` and leave accepted authority
state unchanged.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-clock-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/clock-review/synthetic-clock-accepted-review.json
```

Application is still source-only. It does not read live time, alter host time,
start a clock service, contact a host, or call platform clock adapters.
