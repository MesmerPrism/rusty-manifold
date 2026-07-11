# Peer Identity And Status Authority

Rusty Manifold owns accepted peer identity and low-rate peer status. Sidecars,
Quest adapters, Hostess, and operator tools may propose observations, but they
cannot mutate accepted state, grant roles, decide trust, or issue application
receipts.

The `rusty-manifold-peer` crate provides one deterministic path:

1. A revisioned `rusty.manifold.peer.status_proposal.v1` carries a stable peer
   identity and bounded low-rate status descriptor.
2. The reviewer checks schema identity, authority revision, proposal replay,
   trusted key fingerprint, peer identity, status revision/freshness/TTL,
   role escalation, capability count, and payload plane.
3. Acceptance advances the authority revision exactly once and returns a
   decision, audit event, accepted state, and application receipt.
4. Rejection returns a machine-readable reason, audit event, and unapplied
   receipt without changing the authority revision.

High-rate telemetry, media, command fields, endpoint values, credentials,
pairing material, Android APIs, sockets, and device behavior are outside this
contract slice. Broker admission and topology providers remain later gates.

Public-key credential enrollment is a separate authority from advisory peer
status. See `PEER_ENROLLMENT_AND_DIRECT_LEASE_AUTHORITY.md`; a status
fingerprint or configured-peer record cannot substitute for an enrolled key
and verified reciprocal signature.

Validate with:

```powershell
cargo test -p rusty-manifold-peer
cargo run -p rusty-manifold-schema -- export --check
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_all.ps1
```
