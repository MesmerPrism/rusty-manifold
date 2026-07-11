# Schemas

Peer identity/status authority schemas are exported from the
`rusty-manifold-peer` source contract slice and bind to the peer and peer-review
fixtures. The catalog records contracts only; it does not enable discovery,
sockets, broker admission, or platform behavior.

Runtime-host schema entries bind durable snapshots, command requests, dispatch
and application receipts, explicit expiry receipts, and audit events to the
source-only `rusty-manifold-runtime-host` crate.

Broker product spec and lock entries bind exact feature closure and immutable
fingerprints to `rusty-manifold-broker-product`.

Broker adapter config and receipt entries bind standalone/embedded placement to
one exact product lock while preserving the Runtime Host decision and truthful
adapter/authority labels.

Admission entries bind platform-projected identity, capability grants,
short-lived opaque tokens, one-time use, revocation, expiry, receipts, and
audit to `rusty-manifold-admission`.

Generated schema catalogs live here. Full JSON Schema export can be added after
the catalog and fixtures stabilize.

Schema export must be deterministic. Committed schemas should match the model
crates and fixtures exactly.

```powershell
cargo run -p rusty-manifold-schema -- export --check
```
