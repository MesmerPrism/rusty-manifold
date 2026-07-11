# Peer Enrollment And Direct-Lane Lease Authority

The clean peer path no longer treats an adapter-provided `authenticated=true`
field or a mesh `direct_media_lane_eligible` Boolean as sufficient authority.
`rusty-manifold-peer` now exposes three consecutive, revisioned decisions:

1. An operator route enrolls a stable peer/key record. Manifold validates the
   Ed25519 public key, its SHA-256 fingerprint, peer/trust identity, validity
   window, generation, operator identity, replay id, and authority revision.
   Rotation retires the prior generation; revocation rejects the key
   immediately. Private key material never enters Manifold state.
2. Both enrolled peers sign reciprocal, domain-separated rendezvous statements
   over the same nonce, coordinator epoch, roles, exact topology contract, and
   TTL. Manifold performs strict Ed25519 verification, consumes the nonce and
   evidence ids, and retains the accepted short-lived receipt as authority
   provenance. The receipt records the exact enrollment revision and accepted
   group-owner/client roles. Wrong, rotated, revoked,
   expired, replayed, role-inconsistent, contract-inconsistent, or unregistered
   evidence leaves authority state unchanged.
3. A clean peer-session review consumes that exact retained receipt against
   the current enrollment and rendezvous states. Key rotation/revocation,
   authority advance, pair/role drift, or an unretained/fabricated receipt
   invalidates it even before wall-clock expiry. After accepted mesh
   ranking, the direct-lane authority may issue a real peer-session lease or a
   lease that also names an accepted generic media-session reference. The lease
   binds exact enrollment/rendezvous/mesh/session revisions, selected route,
   canonical pair, expiry, and scope. Media scope also requires an exact valid
   `ManifoldMediaSessionDescriptor`, its current revision, and the selected
   route reference. Eligibility alone, advisory gossip, a stale topology
   receipt, or an ambient media id cannot issue a lease.

Consumers call `validate_current_direct_lane_lease` before platform adoption;
it rechecks the stored lease against every current source authority. Lease
revocation, expiry, key/session/member revocation, or any bound revision drift
therefore fails closed. Request, revocation, nonce, evidence, and sweep ids are
one-use; even a no-op expiry sweep advances authority and consumes its id.

Quest, Termux, sidecar, BLE, and Wi-Fi Direct code remain evidence and platform
adapters. They may sign or transport a proposal but do not enroll keys, consume
nonces, choose current revisions, accept membership, or issue session/media
leases. A configured third peer remains advisory until it has its own enrolled
credential and reciprocal signed evidence.

The source slice is CPU/data-only. It opens no socket, selects no Android
network, carries no endpoint or media payload, and owns no codec. Ed25519
verification is pinned to `ed25519-dalek` 2.1.1 so it remains compatible with
the workspace Rust 1.80 floor; strict verification rejects weak-key and
non-canonical signature cases. Rusty Manifold source remains
`AGPL-3.0-or-later`; `ed25519-dalek` is BSD-3-Clause third-party code and
`sha2` is MIT OR Apache-2.0 third-party code under their own licenses.

Focused validation:

```powershell
cargo test -p rusty-manifold-peer
cargo fmt --all --check
```

The tests cover operator trust, collision, weak/non-canonical keys, generation
overflow, signature tamper, decoded-byte nonce hashing and replay, TTL,
reciprocal roles, contract mismatch, rotation/revocation invalidation,
retained-receipt provenance, signed-session binding, exact mesh membership,
advisory-route rejection, revision drift, accepted media scope, duplicate
issuance, revocation replay, current-lease revalidation, and expiry.
