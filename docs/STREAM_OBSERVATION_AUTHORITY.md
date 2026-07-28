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

## Observation content digest v1

`content_sha256` is `sha256:` followed by the lowercase hexadecimal SHA-256 of
the exact compact UTF-8 JSON serialization of the observation object. Version
1 uses the schema field order shown below, emits no insignificant whitespace,
and emits each Rust `Option` field as its JSON value when present or as the
literal `null` when absent. Implementations must not sort keys, omit null
fields, escape soliduses, append a newline, or hash the surrounding proposal.
The exact field order is `$schema`, `descriptor_type`, `channel_format`,
`channel_count`, `nominal_rate_millihz`, then
`native_descriptor_sha256`.

Committed synthetic test vector (the bytes inside this code block have no
trailing newline in the hashed input):

```json
{"$schema":"rusty.manifold.stream.observation.v1","descriptor_type":"lsl.stream-info","channel_format":"float32","channel_count":8,"nominal_rate_millihz":100000,"native_descriptor_sha256":"sha256:abababababababababababababababababababababababababababababababab"}
```

Its digest is
`sha256:7ac114a4a1922293a9f10031a977c528be0c8e0c11689ca41b3760bacb4cd58d`.

```powershell
cargo test -p rusty-manifold-stream-observation
cargo run -p rusty-manifold-stream-observation --bin stream_observation_conformance -- fixtures/stream-observation/synthetic-conformance-case.json -
```

Fleet and other consumers may project only the resulting accepted state or
Manifold-owned application receipt. A bare proposal or review-only decision is
not consumer authority.
