# Source-selected development lifetimes

`rusty-manifold-admission/contracts/development-lifetime-policy.v1.json` owns
the versioned semantic horizon for delegated new-effect authority. The current
policy selects thirty days, represented as unsigned64 milliseconds. It is not
a task deadline, caller permit, cleanup entitlement or authority registry.

An authority constructor may install the exact record in
`ManifoldAdmissionSnapshot.development_lifetime_policy` and
`ManifoldPeerRuntimeTrustPolicy.development_lifetime_policy`. Mutation requests
cannot select or change it. Altered records reject at construction/restart.
Omission preserves finite defaults and omits the field during serialization;
older strict readers reject selected snapshots rather than silently downgrade.

The accepted selection reaches status and enrollment review, Common-LAN signed
contexts, media acceptance, route acceptance and the corresponding credential,
media and route renewal validators. Legacy Wi-Fi Direct lifetime policy remains
finite. Every expiry still checks actual time. Signature, revocation, current
identity/revision, replay and parent-deadline checks retain their meanings.
The selected horizon is a ceiling: a shorter accepted parent remains shorter.

Owners must renew through their real accepted current-authority transition.
After actual expiry they must perform genuine reauthorization under the
existing eligibility rules; an expired credential is never declared current.
Retained uncertain work is observed or continued under the same owner, never
replayed because a caller stopped waiting. Owned cleanup does not derive its
entitlement from this policy or from a healthy wall clock. Authentication of a
new remote cleanup message is a separate renewable concern.

Focused controls exercise actual admission construction/restart and grant
renewal, actual Ed25519 context review/currentness/replay, status acceptance,
media acceptance and signed fresh setup with retained-state validation.
Platform, transport and device effects remain downstream validation.
