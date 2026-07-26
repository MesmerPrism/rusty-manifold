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

Broker Runtime Host leases are derived state, not a second lease authority.
Normal Broker construction and restart retain a synchronized
`ManifoldBrokerControlLeaseAuthority` containing the current owner view and
exact source applications; no raw Runtime Host lease collection enters those
paths. Durable runtime evidence v5 closes owner evidence v3 and chronological
transition v2 over Host/admission state, lifecycle authorization disposition,
integrated owner/Host receipts, and fail-closed administrative-revocation
barriers. Restart requires a separately supplied non-regressing owner view.
Any pending Host-convergence barrier globally freezes lifecycle authorization
and commit until exact recovery converges it. Provider-epoch rollover carries
all compacted control-lease request identities forward, so an epoch boundary is
not a replay boundary. Released v4 enters only through an explicit
decision-free migration. Platform
lifecycle transport remains a downstream adoption layer rather than a
competing authority. Runtime Host derivative-revocation requests remove
byte-equal downstream lease objects atomically and retain convergence identity,
upstream application, replay, and audit binding; they do not reinterpret the
upstream authority decision.

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
- Bridge routes: transport-neutral intent, delivery semantics, and required
  evidence stages for WebSocket, UDP/OSC, LSL, ADB, file, platform-tooling,
  and media data-plane adapters.
- Data descriptors: stream, packet, frame, and transport metadata.
- Render adoption: resource adoption evidence for visual routes.
- Feedback: health, timing, downgrade reasons, and scorecards.

High-rate payloads move through data-plane transports described by Manifold
metadata. They are not embedded in low-rate command JSON.
