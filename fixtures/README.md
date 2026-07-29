# Fixtures

The `peer/` and `peer-review/` fixtures cover Manifold-owned peer identity,
status proposals, accepted state, decisions, rejections, audit events, and
application receipts. Matching damaged fixtures prove stale authority/status,
replay, untrusted identity, role escalation, high-rate payload, and advisory
command rejection.

The `stream-observation/` conformance case covers non-mutating review,
application-time revalidation, one-step revision advance, and restartable
accepted state/replay/audit lineage. Matching damaged coverage rejects control,
commands, samples/chunks, routes/endpoints, media, permission(s),
product/platform locks, and producer-asserted accepted state/revision.

The `runtime-host/` fixtures prove snapshot/restart parity, command dispatch
and application receipts, explicit lease expiry, v2 control-lease revocation
adoption, derivative-lease convergence, and audit persistence. Accepted
revocation adoption removes only exact leases. Derivative cleanup removes the
complete current set whose accepted binding matches the proof's provider epoch
and upstream control lease. The paired damaged application and substituted
derivative binding are rejected without moving Host lease state. A v3-to-v4
migration receipt proves replay state is initialized without inventing cleanup.
Damaged runtime-host requests also cover unknown commands and missing/expired
leases.
Typed-parameter digest compatibility remains optional in the baseline fixture
documents, while focused Runtime Host tests prove canonical digest propagation,
tamper rejection, and the bounded canonical-size rule.

The `broker-product/` matrix covers the camera-free base, generic camera-free
media session, independent camera, direct-P2P, and BLE profiles, the explicit
legacy camera-plus-P2P compatibility product, exactly-one standalone/embedded
mode, committed lock parity, stale specs, and union-permission rejection.

Fixtures are committed contract examples. They should be small, deterministic,
and safe to use in tests, generated schemas, documentation, and clients.

## Layout

- `host/`: host manifest examples.
- `module/`: module manifest and runtime-state examples.
- `stream/`: stream registry examples.
- `synthetic/`: deterministic synthetic scalar source profiles and generated
  JSONL sample fixtures.
- `stream-subscription/`: stream subscription request, renewal, release, accepted, and rejection examples.
- `command/`: command and lease request, renewal, release, authority-owned
  revocation, acknowledgement, rejection, and remote-camera command handoff
  examples.
- `authority/`: command authority snapshots tying host, clock, stream registry,
  module runtime, command ids, leases, and retained revocation tombstones
  together, including the remote-camera Q2Q session authority snapshot.
- `audit/`: authority audit-event examples.
- `authority-review/`: deterministic command authority review outputs from the fixture CLI, including the remote-camera Q2Q receiver, sender, status, and stop reviews.
- `command-dispatch/`: deterministic source-only command dispatch receipt outputs from the fixture CLI, including the remote-camera Q2Q receiver-first handoff receipts.
- `coordination/`: deterministic coordination session plans, message logs,
  and scorecards for Quest-to-Quest LAN, Quest-to-phone LAN, and remote relay
  two-way streaming.
- `lease-review/`: deterministic lease authority review outputs from the fixture CLI.
- `lease-release-review/`: deterministic lease release authority review outputs from the fixture CLI.
- `lease-renewal-review/`: deterministic lease renewal authority review outputs from the fixture CLI.
- `lease-revocation-review/`: deterministic accepted and authority-mismatch
  administrative lease-revocation reviews.
- `stream-registry-review/`: deterministic stream-registry authority review outputs from the fixture CLI.
- `stream-subscription-review/`: deterministic stream-subscription authority review outputs from the fixture CLI.
- `stream-subscription-release-review/`: deterministic stream-subscription release authority review outputs from the fixture CLI.
- `stream-subscription-renewal-review/`: deterministic stream-subscription renewal authority review outputs from the fixture CLI.
- `authority-expiry/`: authority expiry-sweep request and rejection examples.
- `authority-expiry-review/`: deterministic authority expiry-sweep review outputs from the fixture CLI.
- `authority-application/`: deterministic accepted-state application outputs from the fixture CLI.
- `module-runtime-review/`: deterministic module runtime-state authority review outputs from the fixture CLI.
- `host-manifest-review/`: deterministic host manifest authority review outputs from the fixture CLI.
- `clock-review/`: deterministic clock snapshot authority review outputs from the fixture CLI.
- `graph/`: static graph manifest examples.
- `package/`: package manifest examples.
- `deployment/`: deployment manifest examples.
- `clock/`: clock snapshot examples.
- `validation/`: scorecard examples.
- `host-run/`: install, launch, validation-slot, command, and run-evidence examples for generic host shells.
- `bridge-route/`: transport-neutral bridge route descriptors and evidence
  summaries for command, marker, telemetry, device-management, and media
  data-plane routes.
- `broker-adapter/`: deterministic standalone/embedded configs, product locks,
  and applied/unknown/unleased receipts. Paired receipts deliberately differ in
  placement and lock fingerprint while preserving byte-equivalent Runtime Host
  dispatch/application decisions and `module.runtime.host` authority ownership.
  `runtime-lease-projection.json` is raw evidence for one already applied
  control lease's exact authority/application/audit/retained-state/clock
  provenance. Tests revalidate every field against retained authority-owner
  state before exposing the one-to-one Runtime Host lease. It is not a
  signature, portable proof, or lease issuance path.
  `runtime-evidence-v5.json` is the current deterministic restart evidence. It
  closes owner evidence v3 and transition v2 over the exact Runtime Host lease
  set, admission state, lifecycle authorization/disposition, revocation-use
  invalidations, fail-closed revocation barriers, barrier-recovery receipts,
  terminal consumer acknowledgements, exact committed mutation and
  non-command capability-use receipts, terminal admission-token history,
  the immutable generic-use authorization ledger that closes complete
  use-request/token/grant/client-lock provenance, explicit generic-use
  invalidations, lifecycle receipts, accumulated
  cross-epoch control-lease request replay identities, and provider epoch.
  `runtime-evidence-v4.json` remains
  byte-for-byte as the
  released migration input; its paired revocation-migration receipt binds the
  exact source bytes and decision-free v5 result and records that no barrier
  was synthesized. Neither fixture is a portable freshness claim.
  `runtime-evidence-v3.json` is the released input
  retained for explicit lifecycle migration; its generic pending uses remain
  generic and are never promoted to lifecycle authority.
  `runtime-evidence-v2.json` is a released legacy input retained only for the
  explicit v2 authority-adoption route. Its paired migration receipt
  binds the exact source bytes, typed source, owner lineage, host, canonical
  lease set, adapter/product/clock identities, and resulting current evidence.
  The crate's integrated-runtime tests extend this matrix with bounded-use
  admission, product-unselected and stale work, cross-client/capability damage,
  replay, independent-use survival across unrelated revision advances,
  token-scoped revocation/expiry invalidation, rebind continuity, and
  provider-epoch restart rejection.
- `admission/`: deterministic grant/token lifecycle from issue through one-time
  use, replay rejection, explicit revocation, and post-revocation rejection,
  retained-authority revocation, plus damaged signing-fingerprint and
  capability-escalation requests. The
  signing hashes are synthetic fixture values, never production identities.
- `trusted-local-http-v1/`: sanitized source-only policy, pairing evidence,
  composite command, safe-status, valid-flow, and damaged mappings for one
  wearer-enabled local browser controller. The signed identity is the trusted
  Quest adapter; the browser controller id is a separate logical id. No
  pairing code, password, production token, device-management credential,
  listener, external asset, or player effect is included.
- `shell-handoff/`: contract-backed shell handoff and Manifold review receipt examples for downstream operator or render shells.
- `simulator/`: deterministic source-only simulator snapshots.
- `damaged/`: intentionally invalid examples.

Damaged fixtures are as important as valid fixtures because they prove clients
and validators reject unsafe or ambiguous state.
