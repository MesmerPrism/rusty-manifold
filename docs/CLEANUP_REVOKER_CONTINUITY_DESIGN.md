# Cleanup revoker continuity design

This document identifies the minimum Manifold authority needed when a retained
pair media route still needs cleanup after its original admission grant and
Runtime Host lease expire. It is a source-only contract design. It grants no
platform effect or transport authority.

## Existing boundaries

- A current route expires at its own deadline, and no later than its signed
  peer context, accepted media decision, or exact Runtime Host lease. Reissue
  can replace one leg, retaining the old route as superseded with cleanup
  pending. Route issue does not prove deployment Start or handoff.
- An expired route can be terminalized by the route expiry sweep. Stop and
  explicit revoke require a current route. Pending cleanup may be acknowledged
  by a fresh trusted revoker with a distinct, current media-scope lease, in the
  original authority host and provider epoch.
- Peer Runtime Host can adopt a fresh independent generic control-lease Issue
  application for a trusted revoker. It cannot issue that lease. Broker cannot
  authorize Issue after its only admission grant expires: token issuance is
  bounded by that grant, and Broker exposes no grant replacement mutation.
- Provider epoch rollover requires all current routes and cleanup obligations
  to drain. A crash restore therefore resumes the original externally fenced
  epoch until cleanup completes.

## Required owner transaction

1. Restore the exact Broker and Peer Runtime Host snapshots under one externally
   fenced writer for the retained provider epoch. Reject regressing clocks and
   damaged lineage before any mutation.
2. The trusted deployment owner obtains a fresh cleanup-only credential signed
   by an issuer whose public key and audience were pinned before the original
   Start (or by a separately audited trust-root update). Broker verifies the
   signature and exact requester identity, client lock, original provider
   epoch, original route grant and effect target, allowed cleanup action, fresh
   target challenge, nonce/sequence, current time, and bounded expiry. It
   records the credential and consumed identity under a new durable cleanup
   authority ledger. This does not edit the expired general admission grant.
3. The recovery command path is restricted to expiry terminalization and
   cleanup acknowledgement for that retained target. It may accept a distinct
   revoker principal only through the signed cleanup credential and the
   originally pinned trust root. It neither issues an ordinary admission token
   nor creates a general media Runtime Host lease. In particular, it cannot
   invoke route Issue, media Start, or ordinary lease renewal. Its decision
   joins the immutable route, the credential, and a new revisioned audit event.
4. At an honest time after the old deadline, sweep the original route to
   `Expired` and `Pending`. The cleanup request names its immutable grant ID,
   original provider epoch and platform runtime, plus a new request ID and
   expected route revision. Its cleanup credential proves the distinct,
   current revoker authority. Deployment proves teardown of the original effect
   target and supplies an effect receipt digest. Manifold acknowledges only the
   exact retained target and effect receipt. Replayed or conflicting completion
   cannot advance accepted state.
5. Broker/Peer epoch rollover may follow only after all current media and pair
   route cleanup obligations, including consumer acknowledgements, are drained.

Ordinary grant reauthorization, signed peer-session/topology turnover, accepted media
decision turnover, route replacement, and deployment handoff must happen before
their respective deadlines for continuous service. Every individual grant is
bounded. A continuous service is a sequence of bounded, freshly authorized
epochs and routes; no expired authority is extended in place. The route grant
identities and cleanup records remain immutable across each handoff.

## Failure cases to prove

- Original grant and lease both expire before crash recovery. A new trusted
  cleanup credential still completes cleanup in the same epoch, without a
  general admission token or Runtime Host lease.
- Wrong principal, signing identity, packaged lock, capability subset, route
  grant, platform runtime, authority host, or provider epoch rejects.
- Stale authority revision, repeated request ID, repeated effect receipt,
  regressing clock, future attestation, and expired new grant reject.
- Recovery carries no route Issue or Start permission; an expired original
  client token or renewed original lease cannot satisfy it. A forged issuer,
  changed audience, reused nonce, or stale target challenge also rejects.
- Crash after physical teardown but before acknowledgement retries against the
  same target without a second destructive effect and yields one terminal
  cleanup receipt. Crash after acknowledgement preserves replay rejection.
- A current or cleanup-pending route blocks provider epoch rollover.

The cleanup credential ledger and Broker/Peer integration require source
changes and schema evolution. The existing Peer Runtime Host cleanup API is
sufficient only while a fresh general revoker lease can still be issued; it
does not solve expiry of the sole admission grant. This generic Manifold work
can be implemented and tested independently of a particular application. A
downstream owner must pin the issuer trust root, supply platform identity and
actual effect teardown evidence, and fence native effects by durable process
generation. A credential cannot prove that an earlier process has stopped.
After a reboot, clock-epoch transition needs separately attested continuity;
the owner cannot invent elapsed monotonic time to satisfy Manifold checks.

## Retained registration and live Pending preflight

The source-only Peer Runtime Host now derives the original cleanup projection
from its held accepted route, issue audit, and full genuine Broker admission.
Its immutable field whitelist separates original issue provenance from mutable
route terminalization and admission-release history. Broker authority host and
outer control lease remain distinct from Peer authority host and inner derivative
lease; provenance joins the actual upstream lease and admission-use authorization.
`register_pair_route_cleanup_before_start` sends this derived projection to the
existing complete Broker V6 registry while the original route is current.

`borrow_pending_cleanup` returns a non-cloneable, non-serializable capability
borrowed from the held Broker. The consumed signed event is replay-validated,
and its registration, request, challenge, audit, owner epoch and clock remain
bound. The borrow prevents owner mutation. `preflight_pair_route_cleanup_pending`
requires a fresh independently obtained trusted clock at actual use, rechecks
signed validity and nonregression, and separately checks current Peer route
revision and unified event sequence. A delayed capability cannot extend signed
validity. Expiry of original route authority does not renew it or replace its
immutable issue projection. Completed route cleanup rejects this preflight.

Deployment/effect expectations describe independently retained expected resource
generation, exact leg, platform and digest. Their caller-supplied digest is not
proof that effects existed or ceased. Registration and preflight produce no
terminal receipt, ordinary lease, command dispatch, completion API or verified
teardown. Complete Broker V6 and separate trusted Peer/deployment anchors must
be persisted and jointly reconstructed before resumed effects; library checks
do not prove exclusive storage ownership. Peer has no newly invented clock-epoch
field: the cleanup credential uses the retained Broker clock epoch, and Peer
checks its existing route observation time and provider epoch. Reboot continuity
and terminal executor evidence remain separate contracts.

No released signing payload or V5/V6 snapshot shape changes in this slice.

## Coupled renewal and retained target cleanup

The implemented concurrent renewal path accepts fresh reciprocal signed proof
under current same-key credentials before refreshing those credentials. A
second fresh context renews the same accepted session and original decision.
Outer Broker admission/control and inner media/route renewal retain their
original resource identities and advance only through accepted typed owner
receipts. Ordinary expiry, replay or uncertain application never resets the
original authority or creates a new Start. Histories and deadlines are bounded.

A retained cleanup target is derived from the terminal route and immutable
original issue provenance. Its target holder and lease remain distinct from a
fresh authenticated cleanup requester, including an independently admitted
trusted revoker. Local executor projections use the actual local peer; remote
projections retain their distinct-peer binding. An already prepared Stop can
resume with fresh cleanup authority after original authority expires, while
preserving its original ticket and target.

The platform consumer's signed prepare/commit exchange independently derives
and retains the target Stop action before execution, binds the exact requester
and prepared ticket, and preserves authenticated raw effect readback in the
source completion. These platform proofs do not move physical effect ownership
into Manifold. Replay records prevent a completed effect from running twice;
uncertain effects remain Pending. Route cleanup acceptance still requires the
actual retained effect evidence, and does not prove app camera, GPU or process
teardown. Reboot clock continuity and exclusive durable storage remain separate
requirements from same-process credential renewal.
