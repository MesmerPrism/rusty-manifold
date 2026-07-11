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

When a command has typed low-rate effect parameters, its request includes
`rusty.manifold.runtime_host.typed_params_digest.v1`: the exact parameter type,
canonical SHA-256, and canonical byte count. Review rejects malformed hashes,
size disagreement, and canonical payloads over 4096 bytes. The dispatch and
application receipts preserve the digest byte-for-byte, and `apply_dispatch`
rejects a substituted or omitted binding without advancing the host revision.
The host deliberately does not own or decode platform-specific parameter
values; the typed adapter proves the canonical binding before it calls review.

Broker products select policy and adapters in later units. They must call this
host rather than create parallel accepted state.

The product-facing `ManifoldBrokerRuntime` does not replace this host. It
consumes one accepted admission use, then calls the adapter's single
`review_command`/`apply_dispatch` sequence. Admission rejection never reaches
the host; admitted but unknown, product-unselected, stale, replayed, or
unleased work still produces the normal host receipt. The host remains the
sole command decision and accepted-state owner in standalone and embedded
placement.

```powershell
cargo test -p rusty-manifold-runtime-host
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_all.ps1
```
