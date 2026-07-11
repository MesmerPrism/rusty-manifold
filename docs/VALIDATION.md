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

The peer suite covers operator-enrolled Ed25519 credentials, strict reciprocal
signature review, retained rendezvous provenance, signed peer-session role and
current-revision binding, exact mesh membership, advisory-route rejection,
accepted media-session closure, and current direct-lane lease validation.

For schema or fixture work, rerun the fixture and schema commands directly so
the checked-in generated artifacts stay deterministic:

```powershell
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-fixtures -- emit-synthetic-scalar --check --expected fixtures/synthetic/synthetic-scalar-oscillator-samples.jsonl
cargo run -p rusty-manifold-schema -- export --check
```

For a live broker run, such as the Rusty GPU Viscereality headset E2E path,
start or forward a Manifold broker first, then publish the same bounded
synthetic scalar samples over websocket:

```powershell
cargo run -p rusty-manifold-fixtures -- publish-synthetic-scalar --broker-host 127.0.0.1 --broker-port 8765 --sample-count 40
```

Validation should keep Manifold contract-first. Do not accept a change because
an adapter can tolerate it; the model, fixtures, damaged inputs, and exported
schema catalog must still reject bad state without requiring runtime sockets,
platform SDKs, renderer imports, or high-rate payloads in command JSON. The
explicit live synthetic publisher is a validation adapter for already-running
brokers, not core Manifold authority.
