# Port Order 1 Completion Audit

Date: 2026-06-06

This audit records the current source-only Rusty Manifold authority coverage
against the original broker-port authority checklist. It treats fixtures,
schema catalog entries, model validation, and fixture CLI routes as proof.
Runtime execution, platform adapters, live transports, and downstream
compatibility aliases remain outside Manifold core.

Graph evidence:

- `S:\Work\migration\coding-graph\rusty-manifold-port-order-audit-20260606`

Validation command set:

```powershell
cargo fmt --all
cargo run -q -p rusty-manifold-fixtures -- validate
cargo run -q -p rusty-manifold-schema -- export
cargo test --workspace
cargo fmt --all --check
cargo run -q -p rusty-manifold-schema -- export --check
cargo run -q -p rusty-manifold-fixtures -- simulate --check
cargo run -q -p rusty-manifold-fixtures -- diff --check
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\check_all.ps1
git diff --check
```

## Status Summary

Port Order #1 is complete for the Manifold source-only contract spine. The
authority model has typed review, application, audit, rejection, fixture, schema
catalog, and fixture CLI coverage for command, lease, stream, host, module,
clock, and expiry state. No live runtime, socket transport, host callback,
timer, platform SDK, media stack, or dynamic loader belongs to this completion
claim.

## Proven By Fixtures And Validation

| Requirement | Status | Evidence |
| --- | --- | --- |
| Command envelopes | Proven | `ManifoldCommandEnvelope`, command descriptor fixtures, valid and damaged command validation checks. |
| Command ack/rejection | Proven | `ManifoldCommandAck`, `ManifoldCommandRejection`, accepted/rejected command review fixtures. |
| Command authority review | Proven | `ManifoldCommandAuthorityReview`, command audit event fixtures, stale revision, missing lease, expired lease, unknown command, unknown lease, and capability mismatch checks. |
| Command dispatch receipt | Proven | `ManifoldCommandDispatchReceipt`, ready and rejected receipt fixtures, plus lineage checks for derived receipt/review ids, mismatched snapshot revision, and receipt/request divergence. |
| Control leases | Proven | Lease request, accepted lease, rejection, review, audit, and application fixtures. |
| Lease release | Proven | Release request, stale/unknown/holder/scope/expired checks, review, audit, and application fixtures. |
| Lease renewal | Proven | Renewal request, stale/unknown/holder/scope/zero TTL/non-extending/expired checks, review, audit, and application fixtures. |
| Stream registry | Proven | Registry snapshot, diff, change request, rejection, review, audit, and application fixtures. |
| Active stream/subscription registry guards | Proven | Active stream removal, active transport removal, active UI policy disable, subscriber-limit lowering, unknown module, and unknown endpoint checks. |
| Stream subscription admission | Proven | Subscription request, accepted subscription, zero TTL, stale authority, stale registry, missing capability, unknown stream, unknown transport, subscriber-limit, and UI-policy checks. |
| Stream subscription release | Proven | Release request, accepted release, stale authority, stale registry, unknown subscription, subscriber mismatch, stream mismatch, expired subscription, audit, and application checks. |
| Stream subscription renewal | Proven | Renewal request, accepted renewal, stale authority, stale registry, unknown subscription, subscriber mismatch, stream mismatch, transport mismatch, zero TTL, non-extending, expired subscription, audit, and application checks. |
| Explicit expiry cleanup | Proven | Expiry sweep request, stale authority, registry mismatch, no-expired-state, accepted review, audit, and application fixtures. |
| Module runtime state authority | Proven | Runtime-state request, transition, stale authority, missing lease, expired lease, unknown active stream, missing backend, review, audit, and application checks. |
| Host manifest/capability authority | Proven | Host manifest change request, missing role, unsafe endpoint pairing, expired lease, capability-in-use, backend-in-use, review, audit, and application checks. |
| Clock/timebase authority | Proven | Clock snapshot request, stale authority, expired lease, missing lease, domain mismatch, sequence gap, monotonic regression, review, audit, and application checks. |
| Schema catalog | Proven | `rusty-manifold-schema -- export --check` covers current schema ids and fixture examples. |
| Fixture CLI routes | Proven | `rusty-manifold-fixtures` routes cover review/apply/prepare commands for authority families and are exercised by fixture CLI tests. |
| Cross-family application lineage | Proven | Application validators enforce derived application/review ids, authority revision lineage, registry/runtime/clock lineage where applicable, and accepted-state count guards through a compact model matrix test. |

## Present But Worth Future Hardening

| Area | Current state | Suggested future check |
| --- | --- | --- |
| External consumer round trips | Schema catalog and Rust serde fixtures are deterministic. | Add downstream client round-trip checks when a non-Rust consumer exists. |
| File pressure | `contracts.rs` and fixture `main.rs` have been mechanically split once but remain large. | Continue family-scoped mechanical splits without changing public type names, schema ids, or fixture JSON. |

## Intentionally Out Of Manifold Core

| Area | Reason |
| --- | --- |
| Runtime command execution | Manifold prepares dispatch receipts; downstream hosts execute. |
| Live stream payload transport | Manifold describes stream metadata and subscription authority; payload data planes live in adapters or hosts. |
| Timers and automatic cleanup | Manifold reviews TTL freshness and explicit expiry sweeps; no hidden timers mutate accepted state. |
| Platform SDKs | Android, JNI, OpenXR, ADB, BLE, media stacks, and platform host APIs belong in downstream host or adapter repos. |
| Dynamic plugin loading | Module availability is expressed by manifests and runtime state before any dynamic loading design is accepted. |
| UI authority | GUI surfaces observe and request; Manifold authority owns accepted state and CLI/API-testable command semantics. |

## Downstream Migration Targets

| Target | Manifold handoff |
| --- | --- |
| Hostess transport defaults | Make `rusty.manifold.*` and `/manifold/v1/...` the default lane; keep legacy names as explicit compatibility aliases only. |
| Studio and GUI controls | Route state-changing controls through Manifold command descriptors and shared non-UI command paths. |
| PMB, Polar, Quest, and package processors | Consume Manifold manifests, leases, stream registry, subscriptions, host manifests, module runtime state, clock snapshots, and audit events without re-owning authority. |
| Platform hosts and adapters | Implement execution, transport, permissions, and device behavior behind Manifold-described contracts. |

## Decision

Do not add broad new Manifold authority surface until a downstream consumer
needs it. The next Manifold-only work should be either a small cross-family
lineage-hardening test matrix or continued mechanical family splits to reduce
file pressure. Runtime transport defaults should move to downstream Hostess or
adapter work, not into Manifold core.
