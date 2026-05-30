# Schemas

Generated schema catalogs live here. Full JSON Schema export can be added after
the catalog and fixtures stabilize.

Schema export must be deterministic. Committed schemas should match the model
crates and fixtures exactly.

```powershell
cargo run -p rusty-manifold-schema -- export --check
```
