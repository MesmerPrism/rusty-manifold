# Rusty Manifold

External low-rate stream metadata enters through the
[`rusty-manifold-stream-observation`](docs/STREAM_OBSERVATION_AUTHORITY.md)
proposal/review/application authority. Review is non-mutating; application
revalidates revision, expiry, proposal and policy digests, and the exact
proposer/source/stream binding before advancing exactly once. Proposals cannot
carry samples, commands, routes, media, permissions, product/platform locks,
accepted revision, or accepted state.

Manifold includes a source-only peer identity and accepted low-rate status
authority slice. Sidecars and apps remain proposers; review and application
reject replay, stale revisions/status, untrusted identity, role escalation,
high-rate/media planes, and advisory command fields. See
[docs/PEER_IDENTITY_AND_STATUS_AUTHORITY.md](docs/PEER_IDENTITY_AND_STATUS_AUTHORITY.md).

[Peer-session authority](docs/PEER_SESSION_AUTHORITY.md) turns authenticated,
expiring rendezvous evidence into revisioned accept/reject decisions and
short-lived topology authorization. BLE and platform adapters remain evidence
producers; replay, expiry, revocation, peer substitution, and media capability
requests fail closed before state or topology can advance.

[N-peer mesh authority](docs/PEER_MESH_AUTHORITY.md) accepts bounded
three-to-32-peer membership, elects a canonical coordinator, ranks
authenticated direct routes, rejects split brain, and owns expiry/revocation
and audit. Advisory gossip remains status-only and cannot schedule media.

The opt-in [Peer Runtime Host](docs/PEER_RUNTIME_HOST.md) composes accepted peer
status, enrollment, signed rendezvous, peer session/mesh, topology, and real
direct-lane lease plus product-bound media-session authorities into one restartable snapshot and audit
sequence. It is a source-only compile-time extension; platform, sidecar,
transport, and media-payload behavior remain outside Manifold authority.
Snapshot v2 also joins exact Broker revocation barriers, removes dependent
peer/media state and derivative Runtime Host leases, and retains terminal
cleanup completion before the Broker may checkpoint consumer convergence.

[Media-session authority](docs/MEDIA_SESSION_AUTHORITY.md) binds accepted
source, processor, route, sink, stream, and platform-runtime references while
keeping all high-rate bytes on the binary media plane. Quest lifecycle state
is downstream adoption evidence, not a second Manifold session authority.

The source-only [Manifold Runtime Host](docs/RUNTIME_HOST.md) provides the
durable revision, command review/application, lease-expiry, replay, restart,
and audit engine that later standalone and embedded broker products consume.
Typed low-rate parameter payloads are canonicalized by their adapter and bound
to review, dispatch, and application through an exact digest receipt; Java or
platform code may consume only the receipt-bound payload after application.

[Broker product specs and locks](docs/BROKER_PRODUCTS.md) select exactly one
runtime mode and resolve generic media sessions separately from explicit
camera, direct-P2P, and BLE features into a permission-minimal immutable
closure. The legacy semantic `spec_fingerprint` and the SHA-256 of exact
packaged lock bytes are intentionally separate provenance fields.

[Broker adapters](docs/BROKER_ADAPTERS.md) bind standalone and embedded
placements to that exact lock and route every command through the same Runtime
Host review/application implementation. Their receipts preserve the host
decision and identify the process layer as an adapter, not authority.
Generic control-lease issue, renewal, holder release, authority-owned
revocation, and lease-only expiry are review/application decisions. Revocation
is bound to the exact authority identity, emits a terminal tombstone in
authority snapshot v2, and cannot be reused as a holder release. Runtime Host
adoption v2 revalidates the complete generic application against its exact
prior snapshot and applies the same lease delta once.

Normal Broker construction and restart accept no raw Runtime Host lease
collection. The synchronized Broker owner retains exact generic transitions,
and runtime evidence v5 joins owner evidence v3, Runtime Host state, admission,
lifecycle authorization/disposition, receipts, and fail-closed administrative
revocation barriers. Once generic revocation is accepted, commands and later
lifecycle work for that lease reject even if Host composition still needs
convergence. Any pending Host-convergence barrier globally freezes lifecycle
authorization and commit until its CAS-bound recovery succeeds. Retaining
consumers acknowledge terminal cleanup before rollover can compact their
evidence, while rollover carries accumulated control-lease request identities
forward so a provider-epoch boundary cannot reopen replay.
Released v4 remains an immutable migration input; its explicit
digest-bound v4-to-v5 migration changes schema vocabulary without creating a
lease decision or barrier. One product is capped at 64 projected leases,
4,096 owner transitions, 48 MiB of owner evidence, and 64 MiB of integrated
evidence JSON.
The integrated broker runtime additionally requires a current, client-bound,
capability-scoped one-use admission before any product mutation can reach that
host path. Each bounded use retains the revision that created that use, so an
unrelated client's admission mutation does not invalidate it; exact-token
revocation and expiry remove only derived pending uses. Grants, tokens, and
bounded uses also retain the exact packaged client-lock id/SHA-256.
Direct adapter mutation is crate-private, so external product work enters only
through the integrated runtime gate.
Construction and continuity restore are trusted deployment-owner APIs; the
deployment must externally fence one writable runtime per provider epoch.

[Cross-app admission](docs/ADMISSION.md) binds platform-verified client
identity to explicit capability grants and Manifold-owned short-lived opaque
tokens. Replay, expiry, revocation, capability escalation, and identity
substitution fail closed with revisioned receipts and audit.

The source-only [Local Control Authority](docs/LOCAL_CONTROL_AUTHORITY.md)
composes that admission authority with one generic controller lease and
Runtime Host command acceptance for short, wearer-enabled trusted-LAN control
windows. It starts disabled, exposes only a closed typed command registry, and
never treats HTTP/WebSocket acknowledgement as a player effect.

Rusty Manifold is the typed contract layer for graph, stream, command, lease,
module, host, clock, session, and audit surfaces across the Rusty stack.

This repository starts private and intentionally small. The first slice is
model, documentation, fixtures, and schema policy only. Runtime networking,
dynamic loading, platform SDKs, media stacks, application shells, and UI
frameworks belong in later adapter or product repositories after the contracts
can reject bad state.

## Initial Scope

- Stable names and identifier grammar.
- Versioned manifests and descriptors.
- Command, capability, lease, and rejection vocabulary.
- Remote camera command descriptors plus source-only authority review and
  dispatch receipt fixtures for receiver-first start receiver, start sender,
  status, and immediate stop handoff.
- Coordination-session contracts and simulator fixtures for same-network
  Quest-to-Quest, same-network Quest-to-phone, and remote relay two-way stream
  timing.
- Stream registry and topology fixtures.
- Transport-neutral bridge-route descriptors and evidence summaries that
  classify WebSocket, UDP/OSC, LSL, ADB, file staging, platform tooling, and
  media data-plane roles without opening those transports.
- Synthetic scalar stream sample and oscillator profile fixtures for adapter
  bring-up, plus an opt-in fixture CLI publisher that can send those same
  bounded samples into an already-running Manifold broker for live validation.
- Clock domain and correlation vocabulary.
- Validation scorecards and damaged-input fixtures.
- Supply-chain and provenance fields for packages and adapters.

## Non-Scope

- Runtime daemons or sockets in the core model crates. The fixture CLI's
  explicit `publish-synthetic-scalar` command is a validation adapter, not a
  Manifold authority daemon.
- Dynamic plugin loading.
- Platform SDK dependencies.
- UI or application-shell code.
- Native media, codec, device, or transport dependencies in core crates.
- High-rate binary payloads in JSON command surfaces.

## Repository Shape

- `crates/`: Rust data-contract crates.
- `docs/`: architecture and policy documents.
- `fixtures/`: canonical valid and damaged JSON examples.
- `schemas/`: generated schemas once schema tooling exists.
- `tools/`: validation and export tooling once needed.

## Planning Entry Points

- `docs/IMPLEMENTATION_PLAN.md`
- `docs/COORDINATION_SESSIONS.md`
- `docs/BRIDGE_ROUTES.md`
- `docs/MODULE_PACKAGE_STRATEGY.md`
- `docs/MODULES.md`
- `docs/HOSTS_AND_DEPLOYMENT.md`

## First Validation

```powershell
cargo fmt --all --check
cargo test --workspace
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- emit-synthetic-scalar --check --expected fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl
cargo run -p rusty-manifold-schema -- export --check
```

To drive an already-running local broker with the same synthetic stream shape:

```powershell
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- publish-synthetic-scalar --broker-host 127.0.0.1 --broker-port 8765 --sample-count 40
```
