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

An accepted lease in a Runtime Host snapshot must ultimately retain its
upstream Manifold authority provenance. The Broker adapter's source-only
projector is a borrowed, non-cloneable, one-shot value constructed at the
authority-owning boundary from retained current authority state and a current
bounded healthy clock. It validates an
already applied control lease against the exact prior snapshot, requires it to
remain current, and maps the same id, holder, scope, and expiry one-to-one. A
raw deserialized projection exposes no Runtime Host lease until that state is
freshly revalidated. Runtime Host snapshot construction or restoration does
not issue, accept, renew, release, revoke, or expire that lease. The current
checkpoint supplies this provider contract; making it mandatory for all
Broker construction/restart paths is now enforced by
`ManifoldBrokerControlLeaseAuthority`: normal adapter APIs accept no raw lease
collection and reject restored host leases that differ from owner-derived
projections. Broker runtime evidence v4 retains the chronological owner
transitions, Host/admission state, lifecycle authorization disposition, and
integrated adoption receipts together, and requires a separately supplied
non-regressing owner view during restart. Runtime Host still exposes
compatibility construction and local expiry for non-Broker owners; the Broker
path must not treat either as generic lease authority.

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

For product media admission, the composing peer host calls the owning live
`ManifoldBrokerRuntime` rather than accepting a serialized mutation receipt.
The atomic bridge joins exact packaged product-lock SHA, semantic product
fingerprint, packaged client-lock SHA, platform client identity, command/outer
lease, capability/grant, and Runtime Host receipts before minting an inner
media lease.

Peer enrollment, signed rendezvous, peer session/mesh, and direct-lane lease
state are not compiled into this generic command host. Products that need that
authority select the source-only
[`rusty-manifold-peer-runtime-host`](PEER_RUNTIME_HOST.md) extension at compile
time. The extension reuses the pure peer decisions, owns their combined
restart/audit state, and adds no platform or payload dependency.

```powershell
cargo test -p rusty-manifold-runtime-host
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_all.ps1
```
