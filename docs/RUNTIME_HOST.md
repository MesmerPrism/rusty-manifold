# Manifold Runtime Host v1

`rusty-manifold-runtime-host` is the source-only authority engine for accepted
runtime state. It has no sockets, platform SDKs, dynamic plugin loader, UI, or
product policy.

The host owns a durable revisioned snapshot containing the command registry,
accepted leases, replay identities, and append-only audit events. Command work
is deliberately split:

1. `review_command` checks schema, revision, replay, freshness, registration,
   and required lease identity/scope/holder/expiry without mutation.
2. `apply_dispatch` accepts only a matching receipt reviewed against the
   current revision, advances exactly once, records replay identity, and emits
   an application receipt plus audit event.
3. rejected or stale dispatches leave the accepted revision unchanged.
4. `expire_leases` is an explicit revision-guarded mutation; no hidden timer
   changes accepted state.
5. snapshot JSON round-trips preserve revision, replay guards, leases, and
   audit history across restart.

Broker products select policy and adapters in later units. They must call this
host rather than create parallel accepted state.

```powershell
cargo test -p rusty-manifold-runtime-host
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_all.ps1
```
