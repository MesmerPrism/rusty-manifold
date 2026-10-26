# Finite snapshot construction

Typed factories let adapters construct initial finite data without repeating the
snapshot's replay and audit fields. They preserve the existing finite wire
schemas and `Revision::INITIAL`:

- `ManifoldAdmissionSnapshot::initial(authority_id, grants, root_renewal_policies,
  max_token_ttl_ms)` retains the caller's exact identity, grants and TTL/renewal
  policy and initializes empty token, replay and audit state.
- `ManifoldRuntimeHostSnapshot::initial(host_id, commands, leases)` retains the
  caller's exact host, commands and leases and initializes empty replay and audit
  state. It does not issue, re-admit or authenticate any supplied lease.
- `ManifoldPeerRuntimeTrustPolicy::finite(ManifoldPeerRuntimeTrustPolicyFieldsV1)`
  retains every explicitly supplied policy field. The version-frozen input has
  all existing finite policy fields and supplies no capabilities or defaults.
  It is a typed construction input, not a separate wire schema.

These functions construct data. The existing Authority/Host constructors still
validate it and retain all deployment-owner, source-authority and adoption
requirements. Existing snapshot serialization, expiry, replay, review and
application semantics remain unchanged. The factories are intended for initial
finite state; restoration uses the existing authenticated owner restore routes.

Focused equivalence and damaged-input checks run with:

```powershell
cargo test -p rusty-manifold-admission -p rusty-manifold-runtime-host -p rusty-manifold-peer-runtime-host finite_
```