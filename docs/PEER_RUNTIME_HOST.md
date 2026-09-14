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
  digests across the closed Wi-Fi Direct and common-LAN variants;
- accepted/revoked peer sessions and signed topology authorizations across the
  same mixed authority revision, replay, revocation, and capacity boundary;
- accepted/revoked/expired N-peer mesh membership and ranked direct routes;
- real direct-lane leases and their replay-protected mutations;
- product-bound media-session decisions, directional pair-media-route grants
  with retained cleanup obligations, the embedded media-command Runtime
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
  session instead of accepting a caller-provided authority substitute. Legacy
  direct-lane callers receive a bounded Wi-Fi-only projection; common-LAN
  sessions never enter that legacy API.
- Snapshot v5 stores mixed reciprocal v3, peer-session v2, pair-route v2, and
  tagged signed-topology records. Migration from v4 wraps every retained
  legacy record exactly once as `wifi_direct` while preserving revisions,
  replay sets, provider identity, audit sequence, cleanup history, and all
  unrelated authority state. V1-v3 first retain their existing migration
  rules and then cross the same v4-to-v5 boundary without invented LAN facts.
- Common-LAN review is pure authority. It retains two signed advertised
  listening endpoints, the peer-agreed network-scope identity, and the exact
  route-configuration digest; it opens no socket and treats none of those
  values as observed operating-system state.
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
- Pair-route issue and current readback join the exact live Broker provider
  epoch, client, control lease, media-session decision, current mixed peer
  session/topology, platform runtime specification, and retained resource leg.
  A Broker-derived Runtime Host lease is never treated as ordinary when its
  active retained admission is missing: every live route operation must join
  that admission to the actual current Broker evidence. The legacy v1 route
  API accepts only Wi-Fi Direct records, preserves the original v1 typed
  command digests, and rejects common-LAN records with a schema mismatch.
  Stop and revoke retain unresolved platform cleanup. While the original lease
  remains current its authorized client may complete cleanup; after expiry or
  revocation, cleanup requires a fresh current trusted-revoker command bound to
  the exact retained grant, provider epoch, runtime specification, resources,
  command digest, and effect receipt. Wrong-target, stale, or replayed cleanup
  leaves the pending handle unchanged.
- The Runtime Host joins an exact converged Broker barrier by provider epoch,
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
cargo test --locked -p rusty-manifold-peer-runtime-host
cargo clippy --locked -p rusty-manifold-peer-runtime-host --all-targets --no-deps -- -D warnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_all.ps1
```

The focused tests cover snapshot restart and damage, exact current revisions,
rendezvous/session/direct-lane replay, key rotation recovery, credential
revocation invalidation, split-brain rejection, expiry/sweep replay, mixed
Wi-Fi-to-LAN-to-Wi-Fi ordering, v4 migration and restart damage, a real
peer-session-scoped direct-lane lease, Broker-backed pair-route issue/current/
terminal cleanup including expired and revoked original leases, wrong-target
trusted-revoker rejection, Broker-barrier convergence, derivative
lease lineage and complete-set removal, legacy binding backfill, damaged
binding rejection, and replay-protected terminal cleanup completion.
