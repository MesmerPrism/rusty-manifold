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

## Surfaces

- Control: commands, leases, capabilities, preconditions, and rejections.
- Discovery: package, graph, module, host, and stream descriptors.
- Data descriptors: stream, packet, frame, and transport metadata.
- Render adoption: resource adoption evidence for visual routes.
- Feedback: health, timing, downgrade reasons, and scorecards.

High-rate payloads move through data-plane transports described by Manifold
metadata. They are not embedded in low-rate command JSON.
