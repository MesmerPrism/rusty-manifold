# Stream Observation Authority

Rusty LSL and other external producers may submit typed low-rate stream
metadata as proposals. They do not own accepted Manifold stream state.

The proposal binds a proposer, source, logical stream, canonical observation
content digest, envelope observation time, expiry, and expected current
Manifold revision. Its observation is descriptor metadata only. Unknown fields
fail closed, making accepted revisions or state, application receipts, samples,
chunks, commands, routes, endpoints, media, queues, permissions, packages, and
platform effects structurally invalid.

Review checks current revision, exact policy-owned identity binding, digest,
time window, replay set, schemas, and low-rate bounds. It returns a decision
and separate review audit event without mutating the host. Application accepts
the exact proposal and decision, recomputes digests and identities, rechecks
current revision and expiry, rejects intervening mutation or duplication, then
advances authority exactly once. Rejection returns typed evidence while the
accepted snapshot remains byte-identical.

The restartable host snapshot retains accepted state, applied proposal
identities and digests, and application audit lineage. Restart validation
requires sorted unique state, equal replay sets, bounded collections, and a
gap-free one-revision-per-application audit chain.

```powershell
cargo test -p rusty-manifold-stream-observation
cargo run -p rusty-manifold-stream-observation --bin stream_observation_conformance -- fixtures/stream-observation/synthetic-conformance-case.json -
```

Fleet and other consumers may project only the resulting accepted state or
Manifold-owned application receipt. A bare proposal or review-only decision is
not consumer authority.
