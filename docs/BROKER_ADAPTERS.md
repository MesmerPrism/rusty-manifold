# Broker Adapters

`rusty-manifold-broker-adapter` is the shared adoption boundary between an
accepted broker product lock and `rusty-manifold-runtime-host`. Standalone and
embedded describe process placement only. They do not select different command
rules or own accepted state.

## Authority and binding

An adapter config binds its mode, lock id, semantic lock fingerprint, exact
packaged `product_lock_sha256`, and Runtime Host identity. Construction fails
when the product mode is not exclusive, the mode does not match the lock, the
fingerprint is stale, the Runtime Host command
registry differs from the lock, lease policy drifts, or the adapter claims an
authority owner other than `module.runtime.host`.

The adapter derives registered commands from the exact lock. Read-only peer
status/session-list commands need no lease. Media session, direct-P2P topology,
and BLE rendezvous mutations use stable scoped leases. Both placements call the
same `review_command` then `apply_dispatch` path.

## Lease provenance projection

Control-lease review and application remain the sole generic lease-acceptance
path. `ManifoldBrokerRuntimeLeaseProjector` is a borrowed, non-cloneable,
one-shot authority-owner trust boundary: its constructor must receive the owner's retained current
`ManifoldAuthoritySnapshot` and current clock, rather than state accepted from
a peer, fixture, or serialized projection. It validates that retained state,
then validates a complete `ManifoldControlLeaseAuthorityApplication` against
the exact prior snapshot. The accepted lease must still exist exactly once,
unchanged and active, in retained current state. A current healthy,
non-regressing clock must use the same domain and epoch and remain within the
configured uncertainty bound. Conservative expiry adds rounded-up uncertainty
to the current wall-clock reading. The borrow prevents that owner state from
being mutated while projection is in flight, and projection consumes the
projector so that instance cannot be reused. The public source-only constructor
cannot prove that a caller did not create another projector over stale cloned
state. The Broker adoption slice must keep construction inside the synchronized
authority owner, take a fresh retained-state/clock view for every projection
and deserialized-receipt validation, and prevent this projector from being used
as an ambient adapter-side lease factory.

The resulting
`rusty.manifold.broker.runtime_lease_projection.v1` receipt retains:

- prior, resulting, and retained-current authority revision;
- clock domain, epoch, sequence, projection time, uncertainty, and
  uncertainty-adjusted expiry-check time;
- review, application, and audit identities;
- versioned, domain-separated SHA-256 over the exact typed-JSON serialization
  of prior state, resulting state, retained current state, and the complete
  application, with a deterministic byte limit;
- the complete accepted control lease; and
- a one-to-one Runtime Host lease with the same id, holder, scope, and expiry.

This is projection evidence, not a lease decision, signature, portable proof,
or claim that arbitrary JSON is current. Deserialization produces a raw
receipt whose fields are private. Only revalidation against the retained
authority state and source application returns a wrapper that exposes the
Runtime Host lease. The exact typed-JSON hashes are a versioned wire contract,
not a claim of semantic JSON canonicalization.

The adapter does not issue, renew, release, revoke, reinterpret, or silently
expire a lease, and `ManifoldRuntimeHost::from_snapshot` remains restart
machinery. This source-only checkpoint does not yet remove the pre-existing
raw Runtime Host lease inputs from Broker construction/restart. That adoption
gate, including freshness enforcement for every projector construction,
belongs to the next integration slice.

## Integrated mutation gate

`ManifoldBrokerRuntime` owns the live composition of the exact adapter and
`rusty-manifold-admission`. A successful signature-scoped `authorize_use`
creates one pending bounded use containing the use request id, opaque token id,
client id, packaged client-lock id/SHA-256, exact command capability, resulting
admission revision, and expiry.

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
The receipt preserves both semantic product fingerprint and exact packaged-lock
SHA-256.

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
The committed runtime-lease projection fixture and focused damaged-lineage
tests cover arbitrary insertion, rejected application, substituted derived
ids/holder/scope/expiry/revision, current-state release/renewal, clock
health/epoch/regression/uncertainty, conservative expiry, bounded deterministic
digests, and substitution of every serialized receipt field followed by
mandatory revalidation.
Runtime tests additionally cover product-unselected work, stale Runtime Host
and admission revisions, replay, expiry, cross-client substitution, capability
substitution, revocation, same-provider continuity, and fresh provider epochs.
The suite also proves two clients keep independent bounded uses while the
global admission revision advances, exact-token revocation/expiry invalidates
only derived uses, and typed-parameter digest tamper/oversize cannot advance
Runtime Host state.
