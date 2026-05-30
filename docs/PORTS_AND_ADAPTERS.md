# Ports And Adapters

Manifold ports are typed conversations. Adapters translate those conversations
to concrete protocols, tools, processes, files, or platform APIs.

## Port Families

- Streams for continuous data.
- Commands and services for bounded request/reply.
- Actions for long-running work.
- Parameters for inspectable runtime settings.
- Feedback for health, timing, and adaptation signals.

## Adapter Requirements

Every adapter proposal should declare:

- platform APIs touched;
- process identity and privilege boundary;
- input and output schema ids;
- rate class and queue bounds;
- ownership and release rules;
- failure modes and issue codes;
- fixtures and damaged-input cases;
- provenance and release status.

Core crates must remain usable without optional adapter dependencies.
