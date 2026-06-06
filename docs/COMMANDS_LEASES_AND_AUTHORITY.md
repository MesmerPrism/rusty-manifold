# Commands, Leases, And Authority

Every mutating command is a request to Manifold authority.

## Command Envelope

A command envelope should include:

- command id and name;
- target id and scope;
- input schema id;
- expected graph or registry revision when applicable;
- required capability;
- required lease scope when exclusive;
- preconditions;
- safety class;
- operator-confirmation requirement;
- request timestamp and holder identity.

## Result

Every command produces either an acknowledgement or a rejection. Rejections must
be machine-readable and safe for clients, tools, and UI surfaces to display.

## Authority Review

Command and lease authority review is deterministic and source-only. Given a
`ManifoldAuthoritySnapshot`, `ManifoldCommandEnvelope`, review clock snapshot,
and evidence ids, the evaluator produces a
`ManifoldCommandAuthorityReview` containing either a `ManifoldCommandAck` or
`ManifoldCommandRejection` plus the matching command audit event.
When a command presents a lease, that lease must still be active at the review
clock; an expired lease is rejected even if it is still present in the accepted
snapshot.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-command --snapshot fixtures/authority/synthetic-authority-snapshot.json --envelope fixtures/command/synthetic-command-envelope.json --clock fixtures/clock/synthetic-command-review-clock.json
```

Accepted command reviews are prepared for downstream transport through a
separate source-only dispatch receipt. `ManifoldCommandDispatchReceipt` carries
the reviewed command id, request id, ack or dispatch rejection, and the
reviewed authority decision. It does not advance accepted authority state,
execute the command, start a module, open a transport, or contact a host.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- prepare-command-dispatch --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/authority-review/synthetic-command-accepted-review.json
```

Given a `ManifoldAuthoritySnapshot`, `ManifoldControlLeaseRequest`, review
clock snapshot, and evidence ids, the evaluator produces a
`ManifoldControlLeaseAuthorityReview` containing either a
`ManifoldControlLease` or `ManifoldControlLeaseRejection` plus the matching
lease audit event.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-lease --snapshot fixtures/authority/synthetic-authority-snapshot.json --request fixtures/command/synthetic-lease-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

This route reviews contracts only. It does not execute a module, mutate runtime
state, open transports, contact a host, or depend on legacy broker code.

## GUI And CLI Parity

A GUI control is not the first or only command surface. For every mutating GUI
action:

1. define the command descriptor, input schema, capability, lease scope,
   preconditions, safety class, and acknowledgement or rejection shape;
2. implement the command once in a non-UI path;
3. expose a CLI command that calls that same implementation;
4. make the GUI call that same implementation instead of duplicating logic;
5. test the command through the CLI or command API before judging the GUI.

CLI output must be machine-readable enough for agents to assert accepted,
rejected, issue code, revision, lease, and target state. Manual GUI testing is
for usability, focus, layout, and interaction quality, not for proving command
semantics.

Purely presentational local UI state, such as a collapsed panel or local theme
preview, does not need CLI parity unless it changes persisted state, runtime
state, package state, deployment state, or session evidence.

## Lease Rules

Leases are scoped, expiring, and revision-aware. A UI, API client, tool, or
automation may request a lease, but only Manifold authority accepts, renews,
releases, or rejects it.

The source-only lease reviewer currently rejects requests when:

- the expected revision does not match the authority revision;
- the requested TTL is zero;
- the host does not advertise the requested capability;
- another active lease already holds the requested scope.

Accepted lease reviews are applied through a separate source-only authority
application receipt. The application advances the authority snapshot revision
by one and appends the accepted active lease, or rejects application when the
review itself was rejected.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-lease-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/lease-review/synthetic-lease-accepted-review.json
```

This route does not renew leases, execute commands, mutate runtime state, open
transports, contact a host, or start a lease timer.

Lease renewal uses the same review/application split. A requester submits a
revisioned `ManifoldControlLeaseRenewalRequest` with lease id, holder
identity, expected scope, requested TTL, and renewal reason. The authority
returns either the renewed active lease plus audit event, or a
machine-readable renewal rejection for stale revision, invalid TTL, unknown
lease, inactive lease, holder mismatch, scope mismatch, or a renewal that
would not extend the current expiration. A lease that has already expired at
the review clock cannot be renewed.

The fixture CLI routes are:

```powershell
cargo run -p rusty-manifold-fixtures -- review-lease-renewal --snapshot fixtures/authority/synthetic-lease-active-authority-snapshot.json --request fixtures/command/synthetic-lease-renewal-request.json --clock fixtures/clock/synthetic-command-review-clock.json
cargo run -p rusty-manifold-fixtures -- apply-lease-renewal-review --snapshot fixtures/authority/synthetic-lease-active-authority-snapshot.json --review fixtures/lease-renewal-review/synthetic-lease-renewal-accepted-review.json
```

Accepted renewal application advances the authority revision by one and
replaces exactly the reviewed lease in accepted active lease state with the
renewed expiration. These routes do not execute commands, mutate runtime state,
contact a host, open transports, or start lease timers.

Lease release uses the same review/application split. A requester submits a
revisioned `ManifoldControlLeaseReleaseRequest` with lease id, holder
identity, expected scope, and release reason. The authority returns either the
active lease selected for removal plus audit event, or a machine-readable
release rejection for stale revision, expired lease, unknown lease, holder
mismatch, or scope mismatch.

The fixture CLI routes are:

```powershell
cargo run -p rusty-manifold-fixtures -- review-lease-release --snapshot fixtures/authority/synthetic-lease-active-authority-snapshot.json --request fixtures/command/synthetic-lease-release-request.json --clock fixtures/clock/synthetic-command-review-clock.json
cargo run -p rusty-manifold-fixtures -- apply-lease-release-review --snapshot fixtures/authority/synthetic-lease-active-authority-snapshot.json --review fixtures/lease-release-review/synthetic-lease-release-accepted-review.json
```

Accepted release application advances the authority revision by one and
removes the reviewed lease from accepted active lease state. These routes do
not renew leases, execute commands, mutate runtime state, contact a host, open
transports, or start or stop lease timers.

Stream registry changes use the same authority pattern: request a scoped
`manifold.stream_registry` lease, submit a revisioned
`ManifoldStreamRegistryChangeRequest`, and receive either an accepted registry
snapshot or a machine-readable rejection plus audit event. The registry lease
must still be active at the review clock.

Accepted stream-registry reviews are applied through a separate source-only
authority application receipt. The application advances the authority snapshot
revision by one and installs the accepted stream registry snapshot, or rejects
application when the review itself was rejected.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-stream-registry-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json
```

This route does not publish streams, open transports, notify subscribers,
contact a host, or mutate a runtime registry.

Stream subscriptions use a related authority pattern without an exclusive
control lease. A requester submits a revisioned
`ManifoldStreamSubscriptionRequest` with subscriber identity, subscriber kind,
stream id, transport offer id, TTL, and required subscribe capability. The
authority returns either an accepted `ManifoldStreamSubscription` plus audit
event or a machine-readable subscription rejection for stale revisions, invalid
TTLs, unadvertised subscribe capability, unknown stream or transport, stream
policy, or subscriber-limit conflicts.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-subscription --snapshot fixtures/authority/synthetic-stream-subscription-authority-snapshot.json --request fixtures/stream-subscription/synthetic-stream-subscription-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

Accepted stream-subscription reviews are applied through a separate
source-only authority application receipt. The application advances the
authority snapshot revision by one and appends the accepted active
subscription, or rejects application when the review itself was rejected.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-stream-subscription-review --snapshot fixtures/authority/synthetic-stream-subscription-authority-snapshot.json --review fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json
```

Stream subscription renewal uses the same review/application split. A
requester submits a revisioned `ManifoldStreamSubscriptionRenewalRequest` with
subscription id, subscriber identity, stream id, transport id, expected
stream-registry revision, requested TTL, and renewal reason. The authority
returns either the renewed active subscription plus audit event, or a
machine-readable renewal rejection for stale revisions, invalid TTLs, unknown
subscriptions, subscriber mismatch, stream mismatch, transport mismatch, or a
renewal that would not extend the current expiration.

The fixture CLI routes are:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-subscription-renewal --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --request fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json --clock fixtures/clock/synthetic-command-review-clock.json
cargo run -p rusty-manifold-fixtures -- apply-stream-subscription-renewal-review --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --review fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json
```

Accepted renewal application advances the authority revision by one and
replaces exactly the reviewed active subscription with the renewed expiration.
These routes do not open or close transports, notify subscribers, start
providers, contact a host, or start subscription timers.

Stream subscription release uses the same review/application split. A
requester submits a revisioned `ManifoldStreamSubscriptionReleaseRequest` with
subscription id, subscriber identity, stream id, and release reason. The
authority returns either the active subscription selected for removal plus
audit event, or a machine-readable release rejection for stale revisions,
expired subscription, unknown subscriptions, subscriber mismatch, or stream
mismatch.

The fixture CLI routes are:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-subscription-release --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --request fixtures/stream-subscription/synthetic-stream-subscription-release-request.json --clock fixtures/clock/synthetic-command-review-clock.json
cargo run -p rusty-manifold-fixtures -- apply-stream-subscription-release-review --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --review fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json
```

These routes do not open or close transports, notify subscribers, start
providers, spawn queues, contact a host, or depend on runtime adapters.

Authority expiry sweep is the explicit cleanup path for accepted state that has
aged past the review clock. A requester submits a revisioned
`ManifoldAuthorityExpirySweepRequest` with the expected authority revision and
stream-registry revision. The authority returns either the expired active
leases and active stream subscriptions to remove, or a machine-readable
rejection for stale authority revision, stale registry revision, or no expired
state.

The fixture CLI routes are:

```powershell
cargo run -p rusty-manifold-fixtures -- review-authority-expiry-sweep --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --request fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json --clock fixtures/clock/synthetic-expired-command-review-clock.json
cargo run -p rusty-manifold-fixtures -- apply-authority-expiry-sweep-review --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --review fixtures/authority-expiry-review/synthetic-authority-expiry-sweep-accepted-review.json
```

Accepted expiry-sweep application advances the authority revision by one and
removes exactly the reviewed expired leases and subscriptions from accepted
state. It does not update the accepted clock snapshot, start or stop timers,
open or close transports, notify holders or subscribers, call a host, or depend
on runtime adapters.

Module runtime-state changes also use authority review. A requester must hold
an active module-scoped lease, submit a revisioned
`ManifoldModuleRuntimeStateChangeRequest`, and receive either an accepted
`ManifoldModuleRuntimeState` plus computed transition or a machine-readable
runtime-state rejection plus audit event. The module lease must still be
active at the review clock.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-module-runtime --snapshot fixtures/authority/synthetic-authority-snapshot.json --request fixtures/module/synthetic-runtime-state-change-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

This route reviews proposed contract state only. It does not start or stop a
process, load a module, mutate runtime state, open transports, contact a host,
or depend on legacy broker code.

Accepted module runtime-state reviews are applied through a separate
source-only authority application receipt. The application advances the
authority snapshot revision by one and replaces the accepted module runtime
state, or rejects application when the review itself was rejected.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-module-runtime-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/module-runtime-review/synthetic-module-runtime-accepted-review.json
```

This route does not start, stop, load, unload, signal, contact, or otherwise
control a runtime module.

Host manifest changes use the same authority pattern. A requester must hold an
active `manifold.host_manifest` lease, submit a revisioned
`ManifoldHostManifestChangeRequest`, and receive either an accepted
`ManifoldHostManifest` snapshot or a machine-readable host manifest rejection
plus audit event. The host-manifest lease must still be active at the review
clock.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-host-manifest --snapshot fixtures/authority/synthetic-authority-snapshot.json --request fixtures/host/synthetic-host-manifest-change-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

The source-only reviewer rejects stale revisions, expired or missing leases,
missing authority roles, unsafe endpoint security pairings, capability removals
that would invalidate active leases, command descriptors, or active stream
subscriptions, and backend removals that would invalidate active module
runtime state. It does not probe permissions, open endpoints, start host
services, or depend on Hostess or legacy broker code.

Accepted host manifest reviews are applied through a separate source-only
authority application receipt. The application advances the authority snapshot
revision by one and installs the accepted host manifest, or rejects application
when the review itself was rejected.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-host-manifest-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/host-manifest-review/synthetic-host-manifest-accepted-review.json
```

This route does not probe permissions, open endpoints, start host services,
contact Hostess, or call platform adapters.

Clock snapshots also use authority review before accepted clock state changes.
A requester must hold an active `manifold.clock` lease, submit a revisioned
`ManifoldClockSnapshotChangeRequest`, and receive either an accepted
`ManifoldClockSnapshot` or a machine-readable clock rejection plus audit event.
The clock lease must still be active at the review clock.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-clock --snapshot fixtures/authority/synthetic-authority-snapshot.json --request fixtures/clock/synthetic-clock-change-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

The source-only reviewer rejects stale authority revisions, expired or missing
leases, clock-domain mismatches, non-contiguous sequence changes, and
monotonic time regressions. It does not read a live clock, mutate a time
service, contact a host, or depend on platform adapters.

Accepted clock reviews are applied through a separate source-only authority
application receipt. The application advances the authority snapshot revision
by one and installs the accepted clock snapshot, or rejects application when
the review itself was rejected.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-clock-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/clock-review/synthetic-clock-accepted-review.json
```

This route does not read live time, alter host time, start a clock service,
contact a host, or call platform clock adapters.
