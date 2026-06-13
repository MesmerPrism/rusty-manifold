# Architecture

Rusty Manifold is a contract-first layer for typed runtime coordination.

## Decision

Start with model crates, fixtures, schema policy, and validation vocabulary.
Runtime execution and platform integration come later through adapters.

## Authority

Manifold authority owns accepted mutable state:

- graph revisions;
- module lifecycle records;
- stream registry revisions;
- command accept/reject decisions;
- capability checks;
- control leases;
- clock domains and correlations;
- session evidence;
- audit records.

Clients observe or request through typed commands and descriptors. They do not
mutate accepted state directly.

Remote camera control follows the same rule. Manifold owns source-only command
descriptors, envelopes, authority reviews, and dispatch receipts for receiver
start, sender start, status, and stop. The remote-camera Q2Q fixture sequence
keeps receiver-first ordering explicit at the command handoff layer. Quest owns
platform session/profile contracts, and later adapters execute the accepted
dispatch without moving camera frames through command JSON.

Coordination sessions generalize that receiver-first timing into a reusable
utility. A `ManifoldCoordinationSessionPlan` declares participants, low-rate
coordination transports, inboxes, gates, command refs, media stream refs, and
safety policy. A message log is simulated into a deterministic scorecard for
same-network Quest-to-Quest, Quest-to-phone, or remote relay two-way routes.
Peer mesh and relay health messages are advisory only; command authorization
and media routing remain separate authority and data planes.

## Surfaces

- Control: commands, leases, capabilities, preconditions, and rejections.
- Discovery: package, graph, module, host, and stream descriptors.
- Coordination: low-rate session plans, readiness messages, gates, and
  scorecards.
- Data descriptors: stream, packet, frame, and transport metadata.
- Render adoption: resource adoption evidence for visual routes.
- Feedback: health, timing, downgrade reasons, and scorecards.

High-rate payloads move through data-plane transports described by Manifold
metadata. They are not embedded in low-rate command JSON.
