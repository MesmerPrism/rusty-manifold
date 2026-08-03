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
  `rusty-manifold-admission` and an exact packaged client lock;
- provider-scoped, command-closed surface descriptors;
- derivative per-surface leases bound to one session, controller, provider
  instance, and surface;
- one-time command authorizations with
  `proves_application_effect=false`;
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
4,096 accepted audit events, and 4,096 tombstones. Controller trust is capped
at 366 days, sessions at 30 days, and surface leases at 24 hours. Restart JSON
is capped at 8 MiB. Labels are capped at 96 characters and descriptions at
160 characters.

Every vector that represents a set is strictly sorted and duplicate-free.
JSON decoding rejects unknown fields. Snapshot restart revalidates policy,
cross-object ownership, parent lifetimes, current live/tombstoned identities,
replay order, request digests, event identities, revision sequence, and the
current accepted-state digest.

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
identity, packaged client lock, policy grant, and token expiry.

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
provider-admission and identity substitution rejection, provider-death
cleanup, explicit revocation/expiry, deterministic restart bytes, unknown
field rejection, and snapshot/audit damage rejection.
