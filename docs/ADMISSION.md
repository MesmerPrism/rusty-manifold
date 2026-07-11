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
| Expired access | request, grant, and token clocks plus explicit cleanup sweep | `expired_request`, `grant_expired`, `token_expired` |
| Revoked token reused | retained revoked-token registry | `token_revoked` |
| Java/JNI becomes policy owner | thin identity projection and JNI calls into this crate | static policy-absence and differential tests |

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
