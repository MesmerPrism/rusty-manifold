# Validation

Run the repo-local check before committing changes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\check_all.ps1
```

The check covers:

- `cargo fmt --all --check`;
- `cargo test --workspace`;
- fixture validation through `rusty-manifold-fixtures validate`;
- coordination-session simulation checks through `rusty-manifold-fixtures simulate --check`;
- deterministic fixture diff checks through `rusty-manifold-fixtures diff --check`;
- deterministic synthetic scalar sample checks through
  `rusty-manifold-fixtures emit-synthetic-scalar --check --expected fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl`;
- synthetic scalar live-publisher websocket coverage through
  `cargo test -p rusty-manifold-fixtures publish`;
- schema catalog export checks through `rusty-manifold-schema export --check`.

For narrow model or contract edits, run the focused Rust tests first:

```powershell
cargo test -p rusty-manifold-model
cargo test -p rusty-manifold-fixtures
cargo test -p rusty-manifold-broker-adapter
cargo test -p rusty-manifold-media-session
cargo test -p rusty-manifold-peer
```

The broker-adapter suite includes the integrated authority/admission gate:
bounded one-use admission, token/client/capability/revision/epoch binding,
unknown/unselected/unleased/stale/replay damage, revocation invalidation, and
fresh-provider epoch behavior. It also proves unrelated admission revision
advances preserve independent clients' pending uses while exact-token
revocation/expiry removes only derived uses. The Runtime Host suite covers
canonical typed-parameter digest binding through request, dispatch, and
application plus tamper and 4096-byte limit damage.
The broker-adapter suite also validates the source-only control-lease
projection against exact prior snapshot and application lineage, including
derived review/application/audit ids, one-to-one lease identity, retained
current-state release/renewal invalidation, versioned domain-separated and
bounded provenance digests, clock health/epoch/regression/uncertainty,
conservative expiry, arbitrary insertion, and revalidation after substitution
of every serialized field. Projection is not lease issuance or lifecycle, and
the raw receipt is not a portable proof. Source-only tests do not claim to
authenticate arbitrary caller-supplied or cloned retained state; mandatory
fresh owner-state construction is a Broker adoption gate.
The Broker-owner suite additionally proves that normal construction and
restart accept no raw lease vector, exact source applications reproduce the
host lease set, duplicate and host-only leases reject, authority/clock/lease
regression rejects, v3 owner/host/admission evidence round-trips, ordinary
restore rejects v2, and explicit v2 authority-adoption migration creates no
lease authority.

The peer suite covers operator-enrolled Ed25519 credentials, strict reciprocal
signature review, retained rendezvous provenance, signed peer-session role and
current-revision binding, exact mesh membership, advisory-route rejection,
accepted media-session closure, and current direct-lane lease validation.
The peer Runtime Host suite additionally covers atomic live-broker media lease
minting, stop/release/start generation reuse, exact product/client/app lock
provenance, restart, and damaged receipt rejection.

For schema or fixture work, rerun the fixture and schema commands directly so
the checked-in generated artifacts stay deterministic:

```powershell
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- emit-synthetic-scalar --check --expected fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl
cargo run -p rusty-manifold-schema -- export --check
```

For a live broker run, such as the Rusty GPU Viscereality headset E2E path,
start or forward a Manifold broker first, then publish the same bounded
synthetic scalar samples over websocket:

```powershell
cargo run -p rusty-manifold-fixtures --bin rusty-manifold-fixtures -- publish-synthetic-scalar --broker-host 127.0.0.1 --broker-port 8765 --sample-count 40
```

Validation should keep Manifold contract-first. Do not accept a change because
an adapter can tolerate it; the model, fixtures, damaged inputs, and exported
schema catalog must still reject bad state without requiring runtime sockets,
platform SDKs, renderer imports, or high-rate payloads in command JSON. The
explicit live synthetic publisher is a validation adapter for already-running
brokers, not core Manifold authority.

The trusted-local control source slice additionally runs:

```powershell
cargo test -p rusty-manifold-admission
cargo test -p rusty-manifold-local-control
powershell -NoProfile -ExecutionPolicy Bypass -File .\fixtures\trusted-local-http-v1\Test-TrustedLocalHttpV1Fixtures.ps1
```

These tests are offline. They open no listener and perform no ADB, headset,
APK, browser, discovery, relay, or Fleet operation. They prove disabled
startup, exact adapter/controller identity separation, mandatory pairing-code
verification evidence, explicit unadmitted-window disable, one controller
lease, closed commands, strict typed parameters, replay/rate/expiry/revocation,
composite receipt causality, and a status document without bearer or signing
material.
