# Broker Product Specifications And Locks

`rusty-manifold-broker-product` owns deterministic broker feature resolution.
The product spec selects exactly one runtime mode—standalone or embedded—and
explicit optional feature families. Resolution produces the exact sorted
command, stream, module, and platform-neutral permission closure plus a stable
spec fingerprint.

The semantic `spec_fingerprint` is retained for compatibility and deterministic
closure comparison. It is not an exact packaged-file digest. Packaging computes
SHA-256 over the accepted lock bytes and passes that separately as
`product_lock_sha256`; adapters and media grants must preserve both values
without relabelling either one.

The base standalone product contains only the Runtime Host, peer-status
observation, session listing, generic network access, and the notification plus
background data-sync permissions required by its service lifecycle. It has no
camera, direct-P2P, or BLE capability. `media_session` adds generic media
session/stream/module references without camera permission. `camera_media`
layers the camera module and capture permissions over that generic feature;
direct-P2P and BLE rendezvous add only their own closures. A product may
explicitly compose them, but no consumer may substitute a union lock for a
smaller spec. The broad camera-plus-P2P product is named as legacy validation
compatibility and must be selected explicitly.

Locks are immutable evidence. `validate_broker_product_lock` recomputes the
complete closure and rejects stale, expanded, or otherwise different locks.
Quest maps the accepted permission enum to Android manifest strings; it does
not re-resolve features.

```powershell
cargo test -p rusty-manifold-broker-product
cargo run -p rusty-manifold-broker-product --bin resolve_broker_product -- <spec.json> <lock.json>
cargo run -p rusty-manifold-broker-product --bin export_broker_product_locks -- --out fixtures\broker-product
```

Committed generic media fixtures exist for both standalone and embedded modes;
the embedded fixture does not pull in camera modules or permissions.
