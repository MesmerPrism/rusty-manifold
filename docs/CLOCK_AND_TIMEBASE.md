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
