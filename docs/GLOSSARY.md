# Glossary

- Manifold authority: the component that accepts or rejects mutation and owns
  revisions, leases, registries, clocks, session evidence, and audit.
- Manifest: versioned desired, declared, or observed state.
- Descriptor: a smaller versioned description of one type, port, command,
  stream, endpoint, or tool.
- Fixture: canonical example data used by tests, schemas, docs, and clients.
- Damaged input: an intentionally invalid fixture used to prove rejection.
- Stream: continuous or replayable data described by metadata and carried by a
  separate data plane.
- Command: bounded request with capability, precondition, lease, and rejection
  vocabulary.
- Action: long-running command with progress, cancel, and result surfaces.
- Lease: scoped, expiring authority to request exclusive mutation.
- Scorecard: structured validation evidence for one run, route, or artifact.
