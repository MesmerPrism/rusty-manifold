# Connection Hub Authority

`rusty-manifold-connection-hub` is the source-only durable authority family for
a standalone on-device Connection Hub. It generalizes the short foreground
local-control prototype without changing `rusty-manifold-local-control` or its
released contracts.

## Decision

The Hub keeps one logical controller connection alive across app launches and
physical transport replacement. App processes register bounded UI surfaces as
separately admitted providers. A controller selects a surface through a
derivative lease and every command is checked against the current logical
session, current transport epoch, exact surface/provider instance, lease, and
controller capability.

The authority is transport neutral. It does not open or retain a socket,
listener, HTTP route, WebSocket, Android service, Binder connection, BLE link,
LSL outlet, UI document, media stream, device API, credential, bearer token,
pairing code, or app effect.

## Authority and lifecycle

The accepted snapshot owns:

- durable controller trust records bound to a public-identity SHA-256,
  operator evidence, sorted capabilities, and an explicit expiry;
- logical connection sessions with a stable id and an initial transport epoch
  of one;
- replacement transport evidence whose epoch advances exactly once while the
  logical session and its surface leases remain active;
- provider instances proven by a current accepted
  `capability.connection_hub.provider.register` use in
  `rusty-manifold-admission`, an exact packaged client lock, and the exact
  product-policy provider identity;
- provider-scoped surface descriptors bound to the exact policy-granted
  surface-contract SHA-256 and exact sorted command-to-controller-capability
  registry;
- derivative per-surface leases bound to one session, controller, provider
  instance, and surface;
- one-time command authorizations bound to the lowercase SHA-256 of the exact
  canonical low-rate typed parameters, with
  `proves_application_effect=false`; Manifold retains only the digest, never
  the parameter bytes;
- explicit controller forget, session revoke, provider unregister/death,
  surface unregister, lease release, and trusted-clock expiry cleanup;
- replay ids, exact request digests, tombstones, revision lineage, and audit.

Provider death removes that provider's surfaces and every derivative lease.
Session revoke removes only that session and its leases. Forgetting a
controller removes all of its sessions and leases. Expiry is an explicit
request; no timer mutates authority state implicitly.

## Bounds

One authority retains at most 32 controllers, 32 sessions, 64 providers, 128
surfaces, 256 surface leases, 64 commands per surface, 4,096 replay records,
4,096 accepted audit events, and 4,096 tombstones. Ordinary lifecycle and
command traffic stops at 3,840 accepted events; the final 256 retained slots
are reserved for controller forget, session revoke, provider/surface
unregister, surface-lease release, and expiry. Command spam therefore cannot
make terminal cleanup unavailable, while every accepted request and digest
remains in replay and audit lineage. The same threshold reserves capacity in
all three lockstep collections: applied request ids, applied request digests,
and audit events. Controller trust is capped
at 366 days, sessions at 30 days, and surface leases at 24 hours. Restart JSON
is capped at 8 MiB. Labels are capped at 96 characters and descriptions at
160 characters.

Every vector that represents a set is strictly sorted and duplicate-free.
JSON decoding rejects unknown fields. Snapshot restart revalidates policy,
cross-object ownership, parent lifetimes, current live/tombstoned identities,
replay order, request digests, event identities, revision sequence, and the
current accepted-state digest.

Every `authorize_surface_command` request must carry
`typed_params_sha256` as `sha256:` plus exactly 64 lowercase hexadecimal
characters. The request, audit event, receipt, and command authorization retain
that exact digest. Changing the digest requires a fresh request identity and
produces a different authorization identity; reusing the original request id
with relabelled parameters is rejected as replay. High-rate bytes and the
canonical low-rate parameter bytes remain outside this authority.

## Integration

The Android foreground service is a Quest adapter over this authority. It owns
listener activation, TLS or other confidentiality, address/origin policy,
pairing-code verification, Binder caller evidence, network discovery,
notifications, process lifecycle, and effect receipts. A socket reconnect is
projected as `replace_transport`; it is not a new logical session.

An app provider first consumes the separate Manifold admission capability,
then registers its provider instance and surface. The Hub does not infer an
Android package or signer from request data: registration validates the exact
current admission snapshot, accepted use event, token-bound projected
identity, packaged client lock, policy-granted provider identity, exact
surface-contract digest, exact command-to-capability registry, and token
expiry. A valid lock therefore cannot select a different provider family,
substitute another contract, or lower a command's required controller
capability.

`apply` requires a non-serializable `ManifoldConnectionHubOwnerContext`.
Serialized `requested_at_ms` and `operator_evidence_id` values are audit-bound
projections, not authority: they must exactly match the context's platform
time and fixed verified operator decision. Provider registration must instead
receive the exact current admission snapshot through that context. The Quest
JNI adapter must construct the context inside the retained Hub owner, obtain
time from the platform clock, obtain operator evidence only from the fixed
wearer/owner decision path, and obtain admission state only from its retained
in-process admission owner. It must never deserialize owner context, time,
operator evidence, or admission state from caller, provider, WebSocket, HTTP,
Binder payload, or other remote JSON. The Rust authority rejects a context
mode that does not exactly match the operation.

The additive broker product feature `connection_hub` resolves the standalone
authority, WebSocket transport adapter, low-rate status stream, closed Hub
commands, foreground-service permissions, Internet, and network-state
observation. It deliberately adds no camera, background-camera, BLE,
nearby-Wi-Fi/P2P, Wi-Fi mutation, or media-session authority.

## Validation

```powershell
cargo test -p rusty-manifold-connection-hub
cargo test -p rusty-manifold-broker-product
cargo run -p rusty-manifold-schema -- export --check
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\check_all.ps1
```

Focused tests prove transport replacement with logical-session continuity,
surface-lease continuity, stale-epoch rejection, command replay protection,
provider-admission/identity/provider-family/contract/capability substitution
rejection, command-spam cleanup reservation, provider-death cleanup, explicit
revocation/expiry, deterministic restart bytes, unknown-field rejection, and
snapshot/audit damage rejection.
