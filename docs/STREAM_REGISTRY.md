# Stream Registry

The stream registry is a revisioned view of available streams and their
topology.

## Stream Manifest

Stream manifests should describe:

- stream id and semantic family;
- sample header and schema id;
- source module id;
- rate class;
- timestamp domains;
- retention and replay policy;
- sensitivity level;
- transport offers;
- subscription policy;
- subscriber limits.

## Registry Snapshot

A registry snapshot records one accepted topology revision. It should be
diffable and safe for read-only clients to render without becoming authority.

## Registry Change Review

Stream registry changes are authority-reviewed requests. A
`ManifoldStreamRegistryChangeRequest` carries a request id, holder id, expected
authority revision, registry lease id, required capability, and proposed
`ManifoldStreamRegistryDiff`. The source-only evaluator produces a
`ManifoldStreamRegistryAuthorityReview` containing either an accepted
`ManifoldStreamRegistrySnapshot` or a `ManifoldStreamRegistryRejection` plus a
matching audit event.

The reviewer rejects expired registry leases at the review clock even when the
lease is still present in accepted authority state. Expired lease cleanup is a
separate explicit authority sweep.

When active subscriptions exist, registry review also rejects diffs that remove
an in-use transport offer, disable UI subscription policy while UI subscribers
are active, or lower subscriber limits below the active subscriber count. These
are authority rejections, not runtime transport mutations.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-registry --snapshot fixtures/authority/synthetic-authority-snapshot.json --request fixtures/stream/synthetic-stream-registry-change-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

This route reviews contracts only. It does not publish streams, open
transports, start modules, mutate a live registry, or depend on platform
adapters.

## Registry Application

Accepted reviews are applied to accepted authority state with
`ManifoldStreamRegistryAuthorityApplication`. The source-only application
receipt advances the authority snapshot revision by one, installs the accepted
registry snapshot, and records a machine-readable application rejection when
the review did not accept a registry snapshot.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-stream-registry-review --snapshot fixtures/authority/synthetic-authority-snapshot.json --review fixtures/stream-registry-review/synthetic-stream-registry-accepted-review.json
```

This route still does not publish streams, open transports, notify
subscribers, mutate a live registry, or depend on runtime adapters.

## Subscription Review

Stream subscription is an authority-reviewed admission step. A
`ManifoldStreamSubscriptionRequest` carries a request id, subscriber id,
subscriber kind, expected authority revision, expected stream-registry
revision, target stream id, selected transport offer id, requested TTL,
required capability, and request timestamp. The source-only evaluator produces
a `ManifoldStreamSubscriptionAuthorityReview` containing either an accepted
`ManifoldStreamSubscription` or a `ManifoldStreamSubscriptionRejection` plus a
matching audit event.

The reviewer rejects stale authority or registry revisions, missing subscribe
capability, unknown streams, unknown transport offers, invalid TTLs, UI
subscribers disallowed by the stream policy, and subscriber-limit conflicts.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-subscription --snapshot fixtures/authority/synthetic-stream-subscription-authority-snapshot.json --request fixtures/stream-subscription/synthetic-stream-subscription-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

Accepted reviews are applied to accepted authority state with
`ManifoldStreamSubscriptionAuthorityApplication`. The application advances the
authority snapshot revision by one and appends the accepted active
subscription, or records a machine-readable application rejection when the
review did not accept a subscription.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-stream-subscription-review --snapshot fixtures/authority/synthetic-stream-subscription-authority-snapshot.json --review fixtures/stream-subscription-review/synthetic-stream-subscription-accepted-review.json
```

## Subscription Renewal Review

Stream subscription renewal is a separate authority-reviewed lifecycle step. A
`ManifoldStreamSubscriptionRenewalRequest` carries a request id, subscription
id, subscriber id, expected authority revision, expected stream-registry
revision, stream id, transport id, requested TTL, renewal reason, and request
timestamp. The source-only evaluator produces a
`ManifoldStreamSubscriptionRenewalAuthorityReview` containing either the
renewed active subscription or a `ManifoldStreamSubscriptionRenewalRejection`
plus a matching audit event.

The reviewer rejects stale authority or registry revisions, zero TTLs, unknown
active subscriptions, inactive subscriptions, subscriber mismatches, stream
mismatches, transport mismatches, and renewals that would not extend the
current expiration. A subscription that has already expired at the review
clock cannot be renewed.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-subscription-renewal --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --request fixtures/stream-subscription/synthetic-stream-subscription-renewal-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

Accepted renewal reviews are applied to accepted authority state with
`ManifoldStreamSubscriptionRenewalAuthorityApplication`. The application
advances the authority snapshot revision by one and replaces exactly the
renewed active subscription, or records a machine-readable application
rejection when the review did not renew a subscription.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-stream-subscription-renewal-review --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --review fixtures/stream-subscription-renewal-review/synthetic-stream-subscription-renewal-accepted-review.json
```

These routes do not open or close transports, notify subscribers, start
providers, spawn queues, contact hosts, or depend on runtime adapters.

## Subscription Release Review

Stream subscription release is a separate authority-reviewed lifecycle step. A
`ManifoldStreamSubscriptionReleaseRequest` carries a request id, subscription
id, subscriber id, expected authority revision, expected stream-registry
revision, stream id, release reason, and request timestamp. The source-only
evaluator produces a `ManifoldStreamSubscriptionReleaseAuthorityReview`
containing either the active subscription to remove or a
`ManifoldStreamSubscriptionReleaseRejection` plus a matching audit event.

The reviewer rejects stale authority or registry revisions, expired active
subscriptions at the review clock, unknown active subscriptions, subscriber
mismatches, and stream mismatches. Explicit expiry sweep remains the cleanup
route that removes already-expired subscriptions from accepted state.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-stream-subscription-release --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --request fixtures/stream-subscription/synthetic-stream-subscription-release-request.json --clock fixtures/clock/synthetic-command-review-clock.json
```

Accepted release reviews are applied to accepted authority state with
`ManifoldStreamSubscriptionReleaseAuthorityApplication`. The application
advances the authority snapshot revision by one and removes the released
subscription from the active subscription set, or records a machine-readable
application rejection when the review did not release a subscription.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- apply-stream-subscription-release-review --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --review fixtures/stream-subscription-release-review/synthetic-stream-subscription-release-accepted-review.json
```

These routes do not open or close transports, notify subscribers, start
providers, spawn queues, or depend on runtime adapters.

## Expiry Sweep

Subscription expiry is reviewed explicitly instead of being hidden behind a
runtime timer. `ManifoldAuthorityExpirySweepRequest` carries the expected
authority and stream-registry revisions. Given a review clock, the source-only
evaluator returns either the expired active leases and stream subscriptions to
remove, or a rejection for stale authority revision, stale registry revision,
or no expired state.

The fixture CLI route is:

```powershell
cargo run -p rusty-manifold-fixtures -- review-authority-expiry-sweep --snapshot fixtures/authority/synthetic-stream-subscription-active-authority-snapshot.json --request fixtures/authority-expiry/synthetic-authority-expiry-sweep-request.json --clock fixtures/clock/synthetic-expired-command-review-clock.json
```

Accepted sweep reviews are applied with
`ManifoldAuthorityExpirySweepAuthorityApplication`, which advances the
authority revision and removes exactly the reviewed expired active
subscriptions and leases. It does not open or close transports, notify
subscribers, contact hosts, start providers, or own timer execution.
