# Cross-App Admission

`rusty-manifold-admission` is the accepted-state owner for broker client grants
and session tokens. The selected Quest adapter design is signature-scoped
Binder admission: Android rejects callers outside the broker signing scope,
then projects the Binder UID, package name, and signing-certificate SHA-256 into
`ManifoldClientIdentity`. Manifold still performs the exact grant and token
decision.

## Authority model

- Product/operator configuration owns explicit client grants and capability
  lists.
- Android owns evidence about the immediate Binder caller. A request body is
  never accepted as proof of its own UID, package, or certificate.
- Manifold owns admission revisions, 256-bit opaque token ids, token lifetime,
  one-time capability-use request ids, revocation, expiry, and audit.
- Runtime Host command application remains a separate downstream authority.
  Admission proves that a client may request a capability; it does not prove
  that a command was applied.

For broker mutations, an accepted `authorize_use` is retained by
`ManifoldBrokerRuntime` as a one-use permit. The mutation must present both the
one-use request id and its opaque token id. The permit is bound to the token's
exact client, one derived command capability, the admission revision produced
when that bounded use was created, expiry, and the live provider epoch. Later
unrelated admission mutations may advance the global revision without changing
that binding. Exact-token revocation or expiry removes only permits derived
from the affected token. The permit is consumed before one
Runtime Host review/application attempt. A WebSocket request id, localhost
origin, shared secret, or transport acknowledgement cannot substitute for it.

Tokens are random bearer identifiers retained in accepted broker state. They
bind the exact client identity, source grant, granted capability subset, issue
revision, and expiry. Maximum lifetime is authority policy. Successful issue,
use, revocation, and expiry advance the admission revision once; rejected work
emits audit but does not advance accepted state.

## Threat model and rejection gates

| Threat | Mitigation | Required rejection |
|---|---|---|
| Different app binds to broker | Android signature permission plus exact Binder caller projection | platform denial before Manifold |
| Request lies about package/certificate | service derives identity from sending UID and PackageManager | `identity_mismatch` |
| Client asks beyond its grant | exact subset comparison | `capability_escalation` |
| Token guess or collision | 256 bits from platform `SecureRandom`, collision check against active/revoked ids | `unknown_token` / `token_collision` |
| Token or request replay | consumed issue/use request registries | `replayed_request` |
| Stale client view | expected admission revision | `stale_authority_revision` |
| Unrelated client advances global revision | compare a mutation with its own use-creation revision; retain independent pending uses | no rejection of the unaffected use |
| Expired access | request, grant, and token clocks plus explicit cleanup sweep | `expired_request`, `grant_expired`, `token_expired` |
| Revoked token reused | retained revoked-token registry | `token_revoked` |
| Java/JNI becomes policy owner | thin identity projection and JNI calls into this crate | static policy-absence and differential tests |
| Admitted use copied across clients/commands | client and exact command-capability binding in `ManifoldBrokerRuntime` | `cross_client_use` / `capability_mismatch` |
| Old provider state reused after process death | explicit entropy-derived provider epoch | `provider_epoch_mismatch` |

The design intentionally rejects broad shared secrets and unauthenticated
localhost mutation as product defaults. Network transport and cross-device peer
trust are separate checkpoints.

## Validation

```powershell
cargo test -p rusty-manifold-admission
cargo run -p rusty-manifold-admission --bin export_admission_fixtures -- --out fixtures\admission
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\check_all.ps1
```

Device adapters must additionally prove a same-signer client lifecycle and a
differently signed client denial, preserve logcat evidence, then stop and
uninstall all run-owned packages.
