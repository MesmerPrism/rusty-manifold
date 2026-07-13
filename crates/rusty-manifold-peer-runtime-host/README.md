# Rusty Manifold Peer Runtime Host

This opt-in source-only crate owns the durable runtime composition of
Manifold's pure peer authorities. It retains accepted peer status, operator
enrollment, signed rendezvous, peer sessions, peer mesh, signed topology
authorizations, direct-lane leases, replay guards, and one append-only audit
sequence.

The crate has no Android, Quest, Termux, socket, codec, or media-payload
dependency. Applications select it at compile time by depending on the crate;
the base `rusty-manifold-runtime-host` and pure `rusty-manifold-peer` crates do
not acquire peer-runtime behavior implicitly.

See `../../docs/PEER_RUNTIME_HOST.md` for the authority and restart contract.
