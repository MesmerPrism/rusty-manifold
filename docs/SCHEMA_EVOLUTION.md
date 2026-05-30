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
