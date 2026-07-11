# Broker Adapters

`rusty-manifold-broker-adapter` is the shared adoption boundary between an
accepted broker product lock and `rusty-manifold-runtime-host`. Standalone and
embedded describe process placement only. They do not select different command
rules or own accepted state.

## Authority and binding

An adapter config binds its mode, lock id, lock fingerprint, and Runtime Host
identity. Construction fails when the product mode is not exclusive, the mode
does not match the lock, the fingerprint is stale, the Runtime Host command
registry differs from the lock, lease policy drifts, or the adapter claims an
authority owner other than `module.runtime.host`.

The adapter derives registered commands from the exact lock. Read-only peer
status/session-list commands need no lease. Media session, direct-P2P topology,
and BLE rendezvous mutations use stable scoped leases. Both placements call the
same `review_command` then `apply_dispatch` path.

## Integrated mutation gate

`ManifoldBrokerRuntime` owns the live composition of the exact adapter and
`rusty-manifold-admission`. A successful signature-scoped `authorize_use`
creates one pending bounded use containing the use request id, opaque token id,
client id, exact command capability, resulting admission revision, and expiry.
The mutation request must carry both that use id and token id plus the current
provider epoch; the use id alone is not a bearer credential.

The expected admission revision is the immutable revision that created that
specific bounded use, not the latest global admission revision. Independent
clients therefore retain valid pending uses across unrelated issue/use/revoke
or expiry mutations. Revoking or expiring a token removes only pending uses
derived from that exact token. Before Runtime Host review, the runtime rejects
the wrong epoch, the wrong use-creation revision, unknown/replayed/expired use, token substitution,
cross-client requester, or capability substitution. Once those checks pass,
the use is consumed even if
the Runtime Host subsequently rejects unknown, product-unselected, stale, or
unleased work. This prevents one admitted use from probing or applying more
than one mutation.

`rusty.manifold.broker.mutation_receipt.v1` is the combined verdict. Its
`applied` value is derived only from the preserved Runtime Host application
receipt. Java, JNI, Binder, WebSocket, and process code may project it but may
not create acceptance or authority labels.

## Receipts and platform adapters

`rusty.manifold.broker.adapter_receipt.v1` contains placement and product-lock
identity plus the unmodified Runtime Host dispatch and application receipts.
The process layer is labelled `process_transport_adapter` or
`in_process_adapter`; the authority owner remains `module.runtime.host`.

Quest Java, JNI, socket, and service layers may translate transport inputs into
the typed request and project this receipt back to Android. They must not
reimplement accepted-command, revision, replay, lease, or application rules.
When a platform effect has parameters, the adapter also requires the canonical
typed-parameter digest on the host request and verifies that both preserved
host receipts carry the same digest before returning an effect payload.

## Validation

```powershell
cargo test -p rusty-manifold-broker-adapter
cargo run -p rusty-manifold-broker-adapter --bin export_broker_adapter_fixtures -- --out fixtures\broker-adapter
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\check_all.ps1
```

The committed fixture pairs cover applied, unknown-command, and missing-lease
outcomes. For each pair the standalone and embedded Runtime Host receipts are
identical while placement-specific metadata remains explicit.
Runtime tests additionally cover product-unselected work, stale Runtime Host
and admission revisions, replay, expiry, cross-client substitution, capability
substitution, revocation, same-provider continuity, and fresh provider epochs.
The suite also proves two clients keep independent bounded uses while the
global admission revision advances, exact-token revocation/expiry invalidates
only derived uses, and typed-parameter digest tamper/oversize cannot advance
Runtime Host state.
