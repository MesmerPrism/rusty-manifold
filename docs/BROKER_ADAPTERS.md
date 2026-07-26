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

## Broker-owned projection closure

Normal `ManifoldBrokerAdapter::new` and `restart_from_json` accept a
`ManifoldBrokerControlLeaseAuthority`, never `Vec<ManifoldRuntimeLease>`. That
private-field, non-cloneable owner retains:

- the last synchronized Manifold authority snapshot and clock;
- a bounded, lease-id-ordered set of exact prior snapshots plus accepted lease
  applications; and
- freshly reproduced projection receipts and Runtime Host leases.

Unrelated Manifold leases may remain outside one product, but every lease
installed in that product's Runtime Host must be reproduced from one retained
source application and remain byte-equal in the supplied owner view. Duplicate
projected identities and owner-only or host-only divergence reject.

`rusty.manifold.broker.runtime_evidence.v5` persists v3 control-lease owner
evidence and v2 transitions beside the Runtime Host, admission authority,
generic bounded uses, an immutable authorization record for every successful
generic use, terminal admission-token history, every successfully authorized
lifecycle use, pending lifecycle
permits, explicit invalidations, consumption tombstones, integrated lifecycle
receipts, exact non-command capability-use receipts, and
administrative-revocation barriers. Every retained mutation or non-command
consumption
receipt must reproduce its complete bounded-use object byte-for-byte from the
authorization record, which in turn joins the exact applied admission audit
revision and its complete request/token binding, retained grant/client-lock
identity, capability, and live-or-terminal token identity. Command
capabilities may only enter the Runtime Host mutation path; the generic
capability-consumption path rejects them. Restore requires every authorized
generic use to appear in exactly one of pending, explicitly invalidated,
committed mutation, or committed non-command receipt state. It also requires
the lifecycle authorization ledger to partition exactly into pending,
receipt-completed, or explicitly invalidated uses. These classes are pairwise
disjoint, completed/invalidated uses must be consumption tombstones, and every
receipt must retain the exact originally authorized use. Revocation-caused
invalidations must join their exact barrier and lifecycle/application
identities. Restore does not trust its historical clock as current:
`refresh_from_v2_evidence` requires a separately supplied same-authority,
same-clock-lineage view with non-regressing authority revision, sequence,
monotonic time, wall time, and adjustment count, then replays the chronological
transition ledger and reprojects every product lease.
The library cannot authenticate who supplied that view; keeping it inside the
synchronized authority owner remains a deployment trust boundary.
The public constructor is therefore named
`from_caller_attested_retained_authority_state`; it validates a deployment
attestation but does not manufacture authenticated freshness.

Construction, owner attestation, evidence export, and continuity restore are
trusted deployment-authority APIs, not request-client APIs. The deployment must
externally guarantee one writable Broker runtime per provider epoch across
processes, machines, and durable storage (for example, a storage CAS/fencing
generation or lease service). The explicit restore API is named
`restore_from_caller_attested_exclusive_evidence` to make that obligation
visible. Validation proves internal state closure and non-regression; it cannot
prove snapshot freshness, exclusive storage ownership, or the absence of a
second restored writer. If a trusted owner deliberately forks one snapshot,
one-use guarantees apply independently inside each unsupported split-brain
fork; Manifold makes no global exactly-once claim in that deployment.

One product retains at most 64 projected control leases. Owner evidence is
also capped at 4,096 transitions and 48 MiB of serialized typed JSON before
source reprojection. Authority snapshots are capped at 128 KiB and each exact
transition at 512 KiB. Issue and renewal stop before a 64-transition/32 MiB
cleanup suffix, enough for one accepted cleanup per maximum live product lease.
Rejected generic decisions remain in integrated lifecycle receipts but do not
consume accepted owner-transition capacity. Near the reserve boundary, cleanup
is previewed against both owner and Host and only a fully applicable cleanup
may consume a reserved permit/receipt slot.
Current and legacy integrated runtime JSON entrypoints reject input above
64 MiB before deserialization, and typed runtime restoration enforces the same
aggregate serialized budget before constructing live state.

Issue, renewal, holder release, authority-owned revocation, and explicit
lease-only expiry are admitted through operation-specific capabilities, bound
to the exact compact request digest, provider epoch, token, verified identity,
grant/client lock, expected owner revision, and scope or lease identity.
Holder/requester fields are derived from the verified admission identity;
revocation instead binds the exact current authority identity and a
machine-readable reason. Each attempt consumes its bound use exactly once.
Generic authority rejection retains the exact rejected transition in the
integrated lifecycle receipt without advancing accepted owner state.
Accepted owner state and Runtime Host state commit together; Host rejection or
composition failure discards both accepted candidates while retaining the
consumption tombstone and failure receipt. Expiry binds an exact canonical set
of product lease IDs. A generic sweep that also selects stream subscriptions,
unrelated Manifold leases, or any other lease set is rejected before owner or
Host application.

Administrative revocation has one stricter failure rule. Once the generic
authority has accepted it, the runtime installs a barrier for that exact lease.
Successful Host adoption records a converged barrier. Host rejection or an
unexpected composition error records a pending-host-convergence barrier in the
original accepted owner/Host state. Both states reject commands and later
lifecycle requests for the revoked lease; a composition failure cannot reopen
use while downstream cleanup catches up. The barrier retains the exact generic
transition and, when converged, the matching Host adoption receipt.

One pending Host-convergence barrier freezes lifecycle authorization and
commit globally, not only operations naming the affected lease. Every attempt
rejects with `PendingRevocationConvergence` until the deployment owner resolves
that barrier through recovery; ordinary product mutation cannot bypass or
partially advance around the unresolved owner/Host split.

A deployment owner can retry a pending Host barrier only through an exact
CAS-bound recovery request carrying provider epoch, barrier identity, and
expected owner/Host revisions. Recovery receipts are replay ordered and retain
the exact transition and Host adoption. Rejected recovery receipts stop being
retained before they could consume the final slot needed to converge each
pending barrier; a successful exact recovery can use that reserved slot.
Restart validation recognizes the original composition-failure receipt and its
single exact applied recovery as one closed transition, while rejecting
missing, duplicated, or substituted recovery evidence. Downstream owners do
not mutate the
barrier: after joining a converged barrier and completing their own cleanup,
they return domain-separated convergence and terminal-cleanup receipt digests
in a typed consumer acknowledgement. Products that include the Peer Runtime
Host require its acknowledgement before drained epoch rollover.

Restore binds every accepted Host adoption to its exact nested owner
transition, deterministic adoption identity, Manifold and Host revisions,
operation-specific lease-id delta, and Host audit event, then requires the
complete current Host lease set to equal the current owner set. This checkpoint
does not claim a standalone reconstruction of every intermediate Host lease
object after that object was later renewed or removed; a future chronological
Host-state replay/digest layer can add that historical proof without changing
current accepted-state authority.

After all product leases and pending uses are drained,
`rollover_drained_provider_epoch` remains available without appending another
transition. It checkpoints complete source and result evidence with
domain-separated digests, preserves the exact generic authority
identity/revision/snapshot and clock lineage, preserves Runtime Host state and
replay/audit history, compacts the empty product owner to a new baseline,
invalidates old admission tokens and tombstones through a fresh admission
snapshot, and installs a different provider epoch. Rollover v2 also
checkpoints revocation barriers, terminal consumer acknowledgements, and exact
mutation and non-command capability-use receipts with their immutable
admission-authorization provenance, terminal token history, and generic-use
invalidations.
Its resulting evidence accumulates the prior compacted set
plus source-application, transition-application, lifecycle-receipt, and
authorized-use request identities, and its
`checkpointed_control_lease_request_count` binds the resulting set length.
Later provider epochs reject every accumulated identity as replay; rollover is
therefore a compaction boundary, not a replay boundary. The bounded replay set
must remain within the integrated-runtime capacity. Rollover rejects while any
product lease or pending use remains, any barrier is pending, or a
product-required retaining consumer has not acknowledged terminal cleanup.

Ordinary v4 restore rejects released v2/v3 evidence. Explicit
`from_legacy_v2_evidence_json` migration accepts it only when its exact host
snapshot already closes over separately supplied validated owner lineage. The
migration receipt binds domain-separated SHA-256 for the exact source JSON,
compact typed source, adopted owner lineage, host snapshot, canonical host
lease set, and resulting current evidence plus adapter/product/authority/clock
identities. Its fixed success outcome records that an existing authority was
adopted without a new lease decision. V1 migration remains separately named
and accepts no ambient upgrade through ordinary restore.
A deserialized migration receipt is raw evidence until `validate_against`
recomputes every binding from the source JSON, adapter config, owner evidence,
and resulting current evidence.

Released v4 state enters only through `migrate_v4_evidence_json`. That
migration validates the exact source JSON and current Host closure, upgrades
owner, transition, lifecycle, and Host-adoption schema vocabulary, preserves
all decisions and replay identities, and synthesizes no authority revision,
lease decision, invalidation, or revocation barrier. Its receipt binds the
exact released bytes and resulting typed v5 evidence.

Released v3 state enters through `from_legacy_v3_evidence_json`. Its migration
first applies the Runtime Host v2-to-v3 snapshot migration, adopts the exact v1
owner evidence as the immutable v2 baseline, preserves pending generic command
and capability uses as generic uses, and synthesizes no lifecycle use,
transition, or receipt. This prevents old command permits from becoming lease
authority during upgrade.
Migration `*_sha256` bindings are domain-separated rather than plain hashes of
the artifact alone. Their public framing is UTF-8 domain bytes, one zero byte,
then exact artifact bytes; output is lower-case `sha256:<hex>`. The crate
exports the six versioned `MIGRATION_*_DIGEST_DOMAIN` constants and
`broker_runtime_authority_migration_digest` so independent implementations can
reproduce the wire contract. `product_lock_sha256` retains its existing plain
packaged-byte hash contract.

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

The placement adapter does not issue, renew, release, revoke, reinterpret, or
silently expire a lease, and `ManifoldRuntimeHost::from_snapshot` remains
restart machinery. Normal Broker construction/restart raw-lease inputs are
closed. The integrated runtime is the sole product mutation gate for atomic
owner-driven issue, renewal, holder release, authority revocation, and explicit
lease-only expiry synchronization.

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

The adapter's direct review/apply method is crate-private. External production
consumers cannot construct an adapter and mutate Runtime Host state around this
gate. The feature-gated fixture exporter exposes only one fixed synthetic
fixture set, not an arbitrary command surface.
Composed owners use `commit_mutation`: it reconstructs a private candidate,
commits the one-use Broker decision, and only then exposes immutable
receipt/evidence to an observer. There is no public preview or candidate-copy
API, and an observer error cannot roll back consumption into a repeatable
decision oracle. Peer-host preflight occurs before this point; an unexpected
post-decision composition error leaves peer state unchanged while preserving
the consumed Broker use.

## Source compatibility and upgrade sequence

This checkpoint is an intentional pre-1.0 Rust API and durable-evidence break:
raw Runtime Host lease vectors are no longer accepted by Broker adapter/runtime
constructors, and normal integrated restore accepts only runtime evidence v5.
Downstream callers must:

1. obtain a caller-attested current Manifold authority snapshot and clock;
2. supply the accepted source applications to
   `ManifoldBrokerControlLeaseAuthority`;
3. construct or restore the adapter against that owner;
4. construct `ManifoldBrokerRuntime` with the same owner and admission state;
5. route product mutations only through `ManifoldBrokerRuntime`.

Released runtime evidence v1 through v4 remains separately discoverable in the
schema catalog. It enters only through explicitly named migration functions;
v4-to-v5 additionally emits an exact revocation-migration receipt. No
compatibility shim restores the removed raw-lease authority or fabricates a
revocation barrier.

`rusty.manifold.broker.mutation_receipt.v2` is the combined verdict. Its
`applied` value is derived only from the preserved Runtime Host application
receipt. Java, JNI, Binder, WebSocket, and process code may project it but may
not create acceptance or authority labels.

## Receipts and platform adapters

`rusty.manifold.broker.adapter_receipt.v2` contains placement and product-lock
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
cargo run -p rusty-manifold-broker-adapter --features fixture-export --bin export_broker_adapter_fixtures -- --out fixtures\broker-adapter
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
only derived uses, two retired token ids cannot substitute for exact committed
provenance, every consumed non-command use retains one exact receipt, command
capabilities cannot bypass Runtime Host through that path, rejected recovery
attempts cannot exhaust the final convergence slot, and typed-parameter digest
tamper/oversize cannot advance Runtime Host state.
