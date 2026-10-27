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

## Opted-in finite admission root renewal

The source-selected [development lifetime policy](development-lifetime-policy.md)
uses explicit schema discriminators with unchanged legacy Rust field shapes.
Default finite readers refuse selected markers; policy-aware construction and
restore require the exact independently trusted policy. Requests cannot select
longer authority. Existing finite schema defaults below remain unchanged.

Admission snapshots may explicitly bind `root_renewal_policies` to existing
grant ids. Each finite horizon is a whole minute from five through sixty
minutes; omission retains the five-minute renewal policy. This scoped policy
does not change operation-token TTL limits or bypass current use authorization,
strict deadline extension, identity, scope, or accepted-evidence checks.

The opted-in snapshot field and nondefault `root_renewal_horizon_ms` in retained
grant-renewal bindings require a compatible admission owner and typed reader.
Older strict readers reject these records; there is no downgrade, migration,
or inference of a policy from a long deadline. Default empty policy lists and
five-minute binding fields are omitted during serialization, preserving legacy
fixture bytes. Restart validation requires every retained binding to match its
grant's policy. API requests and real v1 application/adoption receipts retain
their meanings; the policy is authenticated owner state, not a caller TTL grant.

Connection Hub internal policy/request/state/snapshot v3 is an explicit
pre-release transition from v2. It adds fixed authenticated-activity sliding
windows and exact per-session external sequence fences. No v2 snapshot
migration is inferred because v2 lacks the replay lineage needed to construct
those fences. Public Hub WebSocket v1 remains a separate byte-exact contract;
rollover-safe persistent sessions use an additive v2 command/keepalive surface.

Peer reciprocal state v3, peer-session state v2, and pair-media-route state v2
are explicit mixed-topology storage versions. They use strict adjacent-tag
envelopes with unchanged legacy Wi-Fi payload bytes and additive common-LAN
payloads. Their shared top-level revision and replay guards are authoritative;
legacy projections are bounded compatibility views and never fabricate a
standalone legacy history. Unknown tags and extra envelope fields reject.
Migration wraps every retained legacy record without changing its fields,
identities, or signing bytes. New common-LAN schemas use `rusty.manifold.*`
identifiers and do not reuse Wi-Fi Direct group-owner/client fields for
carrier-neutral endpoints or roles.
