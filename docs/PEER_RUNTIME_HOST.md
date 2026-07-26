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
  Host, and retained outer-broker-to-inner-lease admission/release history;
- exact Broker revocation-barrier convergence, media cleanup obligations,
  derivative Runtime Host lease-removal receipts, and terminal cleanup
  completions; and
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
- Snapshot v3 joins an exact converged Broker barrier by provider epoch,
  application, lease, and consumer identity. It revokes dependent peer media
  decisions, sessions, routes, and streams, then atomically removes complete
  byte-equal derivative leases through Runtime Host v4. Each Broker-backed
  inner lease is minted with accepted lineage binding the Broker provider
  epoch, outer control lease, and exact one-use admission authorization.
  Preflight, commit, restart, and convergence revalidate that binding against
  retained Broker grant and use receipts. Runtime Host removes only the
  complete current set matching the revoked outer lease; an unbound,
  unrelated, mixed, or partial set fails closed. Cleanup obligations remain
  durable until a separate replay-protected completion request records
  terminal platform cleanup. Only that completion receipt is suitable for the
  Broker consumer-acknowledgement digest; convergence alone is not cleanup.
- A peer host advances to a fresh drained Broker provider epoch only through
  `rollover_drained_broker_provider_epoch`. The peer verifies the exact Broker
  source/result evidence digests and counts, requires every source-epoch peer
  convergence to have terminal cleanup and an exact Broker acknowledgement,
  retains all convergence and replay/audit history, and appends a peer-owned
  checkpoint digest for the source epoch and immutable audit prefix. Restart
  accepts historical Broker joins only through this ordered checkpoint chain;
  active admissions must always belong to the current live Broker epoch.
- Released snapshots v1 and v2 enter only through explicit migration. V1
  migration initializes empty convergence/cleanup collections; both migrations
  initialize an empty rollover-checkpoint chain without inventing a revocation,
  terminal acknowledgement, or epoch transition. For an active legacy
  Broker-backed admission, migration backfills a derivative binding only when
  the live Broker join proves one exact provider epoch, outer lease, grant, and
  use receipt for the retained inner lease. Ambiguous, damaged, or historical
  pre-binding convergence shapes are rejected rather than assigned invented
  lineage.

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
revocation invalidation, split-brain rejection, expiry/sweep replay, a real
peer-session-scoped direct-lane lease, Broker-barrier convergence, derivative
lease lineage and complete-set removal, legacy binding backfill, damaged
binding rejection, and replay-protected terminal cleanup completion.
