# Schema Evolution

Manifold starts with JSON fixtures and deterministic schema export.

## Policy

- Schema ids use `rusty.manifold.<family>.<name>.v<major>`.
- Major versions change when a consumer must change behavior.
- Removed field meanings are never reused.
- Unknown enum variants need safe rejection or downgrade behavior.
- API messages, storage records, and evidence records remain separate when
  their compatibility needs diverge.
- Fixtures are part of the compatibility contract.

Binary formats, HTTP descriptions, event descriptions, and language bindings
can be generated later from stable Manifold contracts.

Connection Hub internal policy/request/state/snapshot v3 is an explicit
pre-release transition from v2. It adds fixed authenticated-activity sliding
windows and exact per-session external sequence fences. No v2 snapshot
migration is inferred because v2 lacks the replay lineage needed to construct
those fences. Public Hub WebSocket v1 remains a separate byte-exact contract;
rollover-safe persistent sessions use an additive v2 command/keepalive surface.
