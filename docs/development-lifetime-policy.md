# Source-selected development lifetimes

`rusty-manifold-admission/contracts/development-lifetime-policy.v1.json` owns
the versioned semantic horizon for delegated new-effect authority. The current
policy selects thirty days, represented as unsigned64 milliseconds. It is not
a task deadline, caller permit, cleanup entitlement or authority registry.

Legacy public Rust snapshot, trust-policy and runtime-context shapes remain
unchanged. Existing constructors and context functions retain finite defaults.
Selection uses an explicit discriminator in existing schema fields:

- Admission `development_snapshot.v1`, or `development_snapshot.v2` once actual
  ongoing ownership is established, in the `rusty.manifold.admission` family.
- Peer `rusty.manifold.peer.runtime_host.development_trust_policy.v1` in the
  existing nested trust-policy schema field. The enclosing snapshot version
  still identifies its actual fresh/ongoing storage contract.

A marker is not permission. Selected construction and raw restore require the
exact independently trusted source policy through additive `_with_lifetime_policy`
APIs. Default finite restore refuses selected data; selected restore refuses a
finite marker or altered policy. Actual owned-history restore still requires
its independent live-owner anchor, which also retains the accepted selection.
No snapshot envelope, extra legacy field or policy inferred from a long deadline
is introduced. Accepted owners expose `development_lifetime_policy()`; a raw
snapshot is evidence, not an admitted owner.

Policy-aware reciprocal, media and route review functions take accepted policy
separately from their unchanged runtime context. The Peer owner supplies that
selection to its actual pure reviewers, including ongoing signed plans and
credential/media/route renewal. Legacy Wi-Fi Direct lifetime policy remains
finite. Every real expiry still checks actual time. Signature, revocation,
identity/revision, replay and parent-deadline checks retain their meanings.
The horizon is a ceiling: a shorter accepted parent remains shorter.

Owners renew through their real accepted current-authority transition. After
actual expiry they require genuine reauthorization under existing eligibility
rules; expired evidence is never declared current. Uncertain work is observed
or continued under its same owner. Caller cancellation is not remote completion.
Owned cleanup does not derive entitlement from this policy or a healthy wall
clock. Authentication of a new remote cleanup message is separate and renewable.

Focused controls compile unchanged pre-policy public literals and exercise
actual admission/grant renewal, selected restore/no-downgrade, retained Broker
construction through its ongoing join, Ed25519 review/currentness/replay, media
acceptance and fresh setup through the actual owned signed-history path.
Platform, transport and device effects remain downstream validation.
