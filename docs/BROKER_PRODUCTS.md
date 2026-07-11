# Broker Product Specifications And Locks

`rusty-manifold-broker-product` owns deterministic broker feature resolution.
The product spec selects exactly one runtime mode—standalone or embedded—and
explicit optional feature families. Resolution produces the exact sorted
command, stream, module, and platform-neutral permission closure plus a stable
spec fingerprint.

The base product contains only the Runtime Host, peer-status observation,
session listing, and generic network permission. It has no camera, direct-P2P,
or BLE capability. Camera/media, direct-P2P, and BLE rendezvous descriptors add
only their own closures. A product may explicitly compose them, but no consumer
may substitute a union lock for a smaller spec.

Locks are immutable evidence. `validate_broker_product_lock` recomputes the
complete closure and rejects stale, expanded, or otherwise different locks.
Quest maps the accepted permission enum to Android manifest strings; it does
not re-resolve features.

```powershell
cargo test -p rusty-manifold-broker-product
cargo run -p rusty-manifold-broker-product --bin resolve_broker_product -- <spec.json> <lock.json>
```
