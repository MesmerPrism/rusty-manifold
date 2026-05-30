# Tools

The first executable tooling lives in `crates/rusty-manifold-fixtures`.

Tools should be deterministic, non-interactive by default, and safe for agents
to run in continuous validation.

```powershell
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
```
