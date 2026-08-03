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
  product-policy provider identity. The short-lived credential must be live at
  registration, but its later expiry does not kill the admitted process
  instance. Provider lifetime ends only through exact unregister, Binder/process
  death cleanup, or restart reconciliation;
- provider-scoped surface descriptors bound to the exact policy-granted
  surface-contract SHA-256 and exact sorted command-to-controller-capability
  registry;
- derivative per-surface leases bound to one session, controller, provider
  instance, and surface;
- one-time command authorizations bound to each command's exact typed-parameter
  schema id and packaged schema SHA-256 plus the lowercase SHA-256 of the exact
  canonical low-rate typed parameters, with
  `proves_application_effect=false`; Manifold retains only the digest, never
  the parameter bytes;
- explicit controller forget, session revoke, provider unregister/death,
  surface unregister, lease release, and trusted-clock expiry cleanup;
- epoch-scoped replay ids, exact request digests, tombstones, revision lineage,
  chained history checkpoints, and audit.

Provider death removes that provider's surfaces and every derivative lease.
Admission-token expiry alone does not remove a live provider or cap a surface
lease; the session remains the lease lifetime parent. The platform adapter must
therefore issue exact unregister on Binder death and reconcile retained
providers against live Binder/process instances after restart.
Session revoke removes only that session and its leases. Forgetting a
controller removes all of its sessions and leases. Expiry is an explicit
request; no timer mutates authority state implicitly.

## Bounds

One authority retains at most 32 controllers, 32 sessions, 64 providers, 128
surfaces, 256 surface leases, 64 commands per surface, 4,096 current-epoch
replay records, 4,096 current-epoch accepted audit events, and 4,096 current-
epoch tombstones. Ordinary lifecycle and command traffic reaches its rollover
gate at 3,840 accepted events; the final 256 slots remain reserved for cleanup
and the owner-only `rollover_history` operation. Rollover advances an exact
authority epoch, checkpoints ordered request ids/digests/events and compacted
tombstones through one constant-size SHA-256 chain link, and clears only those
bounded historical collections. It leaves live controllers, sessions,
providers, surfaces, and leases byte-exact.

Every request id and newly created durable object id is prefixed by its exact
authority epoch. A prior-epoch request remains rejected even if a caller
changes the serialized epoch field, because its id prefix no longer matches.
Provider admission replay is independently fenced by the exact current
admission-authority revision captured at rollover. A use event at or below that
floor can never register a new provider. These namespace and revision fences,
not a lossy probabilistic set, keep all compacted request/admission-use replay
identities closed. Controller trust is capped
at 366 days, sessions at 30 days, and surface leases at 24 hours. Restart JSON
is capped at 8 MiB. Labels are capped at 96 characters and descriptions at
160 characters.

Every vector that represents a set is strictly sorted and duplicate-free.
JSON decoding rejects unknown fields. Snapshot restart revalidates policy,
cross-object ownership, parent lifetimes, current live/tombstoned identities,
replay order, request digests, event identities, revision sequence, and the
current accepted-state digest.

Every registered command binds `typed_params_schema_id` and
`typed_params_schema_sha256`. The authority-internal
`authorize_surface_command` request must echo that exact pair and carry
`typed_params_sha256` as `sha256:` plus exactly 64 lowercase hexadecimal
characters. Schema substitution rejects before authorization. The request,
audit event, receipt, and command authorization retain all three bindings.
The explicit zero-argument schema hashes the exact committed schema bytes and
accepts only canonical `{}`
(`sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`);
an omitted argument object is not equivalent.

`fixtures/connection-hub/typed-params-canonical-vectors.v1.json` is the shared
cross-language oracle. Version 1 accepts an object root, ascending ASCII keys,
null/boolean/safe-integer/ASCII-string scalar values, no insignificant
whitespace, and UTF-8. Providers may publish a narrower schema but may not
change canonicalization. High-rate bytes and canonical parameter bytes remain
outside this authority.

## Integration

The Android foreground service is a Quest adapter over this authority. It owns
listener activation, TLS or other confidentiality, address/origin policy,
pairing-code verification, Binder caller evidence, network discovery,
notifications, process lifecycle, and effect receipts. A socket reconnect is
projected as `replace_transport`; it is not a new logical session.

Policy and construction bind the exact admission authority id plus Broker
product-lock id, semantic fingerprint, and SHA-256 of the exact packaged lock
bytes. `new` and `restart_from_json` require the retained admission authority,
decoded product lock, and packaged bytes and reject any substitution or
admission revision regression.

An app provider first consumes the separate Manifold admission capability,
then registers its provider instance and surface. The Hub does not infer an
Android package or signer from request data: registration validates the exact
current admission snapshot, accepted use event, token-bound projected
identity, packaged client lock, policy-granted provider identity, exact
surface-contract digest, exact command-to-capability registry, and token
expiry. A valid lock therefore cannot select a different provider family,
substitute another contract, or lower a command's required controller
capability.

The free `OwnerContext` constructor and public generic `apply` route do not
exist in v2. `authority.owner()` returns a borrowed, non-serializable mutation
boundary with explicit lifecycle, operator-decision, provider-admission, and
history-rollover methods. Only the provider and rollover methods accept the
retained `ManifoldAdmissionAuthority`; no caller-supplied snapshot can enter.
Serialized time, epoch, operator evidence, product fields, schema bindings,
and digests are audit projections, not owner evidence. The Quest JNI adapter
derives them from platform time, the fixed wearer decision path, the retained
admission owner, the registered descriptor, and exact packaged assets.

The already sealed controller/Hostess WebSocket v1 is unchanged. Its canonical
`arguments` object remains the public input. Quest canonicalizes those bytes,
derives the current Manifold epoch/request namespace and registered schema
binding internally, then calls this owner. A controller never supplies an
authority epoch, product-lock fingerprint, admission revision, or parameter-
schema digest.

## Authority schema transition

The internal policy/request/state/snapshot family advances from v1 to v2.
There is deliberately no field-inference migration: v1 snapshots do not carry
the exact product-lock bytes, admission revision floor, command schema bytes,
or replay namespace needed to construct v2 safely. The current pre-release Hub
must initialize a fresh v2 authority from exact packaged inputs before first
deployment. A v1 build may be rolled back only with its untouched v1 snapshot;
after any accepted v2 mutation, downgrade is prohibited. The public Quest/
Hostess WebSocket v1 is a separate contract and remains compatible.

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
rejection, exact owner/product/admission bindings, provider lifetime beyond its
registration credential, command-schema substitution rejection, canonical
zero-argument vectors, repeatable history rollover with active-state
preservation and prior replay closure, command-spam cleanup reservation,
provider-death cleanup, explicit revocation/expiry, deterministic restart
bytes, unknown-field rejection, and snapshot/audit damage rejection.
