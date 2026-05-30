# Interactive Media Routes

Interactive media routes separate control, high-rate payload movement, render
adoption, and feedback.

## Planes

- `control`: low-rate negotiation, permissions, selected backend, leases, and
  status.
- `media_data`: encoded packets, raw samples, audio chunks, or binary
  diagnostics carried outside command JSON.
- `render_adoption`: decode, queueing, resource import, projection metadata,
  stale-frame reuse, and submission ownership.
- `feedback`: route health, adaptation hints, issue codes, and scorecards.

## Evidence States

Keep separate lifecycle states for:

- encoded packet;
- decoded frame;
- raw diagnostic frame;
- imported buffer or texture;
- adopted render frame;
- submitted visual frame.

Transport and decode evidence is not the same as final visual adoption.
