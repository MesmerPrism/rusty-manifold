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
