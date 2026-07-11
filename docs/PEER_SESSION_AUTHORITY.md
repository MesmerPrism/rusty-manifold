# Peer Session Authority

`rusty-manifold-peer` owns acceptance of authenticated, expiring peer-session
proposals. Transport adapters only project evidence; BLE, Wi-Fi Direct,
Android, ADB, and application shells do not advance accepted peer state.

The authority path is proposal → review → decision → accepted state → scoped
topology authorization. Review binds the expected authority revision, stable
peer pair, accepted peer capabilities, trusted adapter, authenticated evidence
digest, observation/expiry window, low-rate capability set, and topology
contract. Only an accepted decision advances the revision. Rejection leaves
state unchanged; replay, expiry, revocation, unauthenticated evidence,
high-rate/media capability requests, stale revisions, and peer substitution
fail closed.

The resulting `rusty.manifold.peer.topology_authorization.v1` receipt is a
short-lived capability, not topology state. A downstream provider must require
`authorized=true`, the current authority revision, a fresh validity window,
the exact topology contract and the local peer's assigned role before any
platform topology mutation. Explicit revocation advances the revision and
emits a non-authorizing receipt, invalidating earlier receipts even if their
wall-clock expiry has not elapsed.

Validation remains source-only:

```powershell
cargo test -p rusty-manifold-peer
```

Canonical and damaged fixtures live under `fixtures/peer-session/` and
`fixtures/damaged/peer-session-*.json`. Runtime BLE and Wi-Fi Direct adapters
belong in downstream platform repos.
