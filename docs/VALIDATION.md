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
- schema catalog export checks through `rusty-manifold-schema export --check`.

For narrow model or contract edits, run the focused Rust tests first:

```powershell
cargo test -p rusty-manifold-model
cargo test -p rusty-manifold-fixtures
```

For schema or fixture work, rerun the fixture and schema commands directly so
the checked-in generated artifacts stay deterministic:

```powershell
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
cargo run -p rusty-manifold-schema -- export --check
```

Validation should keep Manifold contract-first. Do not accept a change because
an adapter can tolerate it; the model, fixtures, damaged inputs, and exported
schema catalog must still reject bad state without runtime sockets, platform
SDKs, renderer imports, or high-rate payloads in command JSON.
