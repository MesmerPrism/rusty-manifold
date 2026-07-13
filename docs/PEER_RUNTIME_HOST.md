# Manifold Peer Runtime Host

`rusty-manifold-peer-runtime-host` is the opt-in, source-only runtime owner for
the pure decisions in `rusty-manifold-peer`. Depending on this crate is the
compile-time feature selection: the base model, peer, and Runtime Host crates
do not acquire peer-runtime behavior implicitly.

## Owned State

One durable snapshot retains:

- accepted low-rate peer identity and status;
- operator-mediated public credentials and enrollment replay ids;
- accepted reciprocal signed-rendezvous receipts, evidence ids, and nonce
  digests;
- accepted/revoked peer sessions and signed topology authorizations;
- accepted/revoked/expired N-peer mesh membership and ranked direct routes;
- real direct-lane leases and their replay-protected mutations;
- product-bound media-session decisions, the embedded media-command Runtime
  Host, and retained outer-broker-to-inner-lease admission/release history; and
- one strictly ordered, append-only audit sequence spanning every authority
  family.

The wrapper constructs each review case from its own current state, calls the
existing pure authority, adopts only the returned accepted state, and records
the exact prior/resulting revision plus serialized rejection code. It does not
reimplement enrollment, signature, session, mesh, route, or lease decisions.

## Current-Revision And Restart Rules

- Every request still carries the owning pure authority revision. Stale and
  replayed work returns that authority's typed rejection without advancing its
  lane revision.
- Credential rotation or revocation does not silently rewrite historical
  receipts, sessions, or leases. Current-state validation rejects their old
  enrollment/rendezvous bindings, and fresh signatures are required before a
  new session or lease can advance.
- Signed topology authorizations are retained only from accepted signed peer
  sessions. Direct-lane issuance resolves the topology from the host-owned
  session instead of accepting a caller-provided authority substitute.
- Mesh expiry ids are replay-protected by the host audit sequence because the
  pure mesh sweep intentionally owns only membership mutation. Direct-lane
  sweep ids remain protected by the lease authority itself.
- Snapshot restart validates schemas, sorted/unique identities, replay sets,
  session/rendezvous/topology provenance, lease references, and exact audit
  continuity before exposing state.
- Media start is a two-state atomic transaction: the host clone-invokes the
  owning live BrokerRuntime mutation, revalidates complete adapter/dispatch/
  application/current-use evidence, mints a short-lived inner lease, and
  commits both states only on success. Stop/revoke precedes replay-guarded
  release. A fresh bounded use may start the same immutable grant again after
  release while older generations remain audit history.

## Boundary

The crate has no Android, Quest, Termux, sidecar, socket, transport, codec, UI,
or media-payload dependency. An optional generic media-session descriptor is a
low-rate authority reference consumed by the existing direct-lane validator;
no frame, packet, endpoint, or platform lifecycle moves into this host.

`rusty-manifold-runtime-host` remains the generic command/lease engine. The
peer host is a modular sibling extension with peer-specific state; products
may compile one or both, but adapters may not create a third accepted-state
owner.

## Validation

```powershell
cargo test -p rusty-manifold-peer-runtime-host
cargo clippy -p rusty-manifold-peer-runtime-host --all-targets --no-deps -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_all.ps1
```

The focused tests cover snapshot restart and damage, exact current revisions,
rendezvous/session/direct-lane replay, key rotation recovery, credential
revocation invalidation, split-brain rejection, expiry/sweep replay, and a
real peer-session-scoped direct-lane lease.
