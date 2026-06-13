# Ports And Adapters

Manifold ports are typed conversations. Adapters translate those conversations
to concrete protocols, tools, processes, files, or platform APIs.

## Port Families

- Streams for continuous data.
- Commands and services for bounded request/reply.
- Actions for long-running work.
- Parameters for inspectable runtime settings.
- Feedback for health, timing, and adaptation signals.
- Coordination sessions for low-rate readiness, advisory peer status, relay
  status, and scorecard evidence.

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

## Coordination Adapters

Coordination adapters translate a `ManifoldCoordinationSessionPlan` into
platform-specific readiness checks and return a `ManifoldCoordinationMessageLog`
or scorecard evidence. Quest, Android phone, Termux, and remote relay adapters
must keep Manifold's boundary intact:

- control messages remain low-rate metadata;
- peer mesh and relay status are advisory only;
- sender start is authorized only after receiver-readiness gates pass;
- camera 50/51 media payloads move through media-plane transports, not
  coordination JSON;
- live adapters require operator review before using real devices or relays.

## Command Surface Parity

GUI, CLI, API, MCP, and tests are adapters over the same command descriptors.
A runtime mutation should not exist only behind a GUI event handler. Build the
CLI route with the command so an agent can validate behavior deterministically,
then use GUI testing to judge human usability and platform interaction quality.
