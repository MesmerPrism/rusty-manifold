# Tools

The first executable tooling lives in `crates/rusty-manifold-fixtures`.

Tools should be deterministic, non-interactive by default, and safe for agents
to run in continuous validation.

```powershell
cargo run -p rusty-manifold-fixtures -- validate
cargo run -p rusty-manifold-fixtures -- simulate --check
cargo run -p rusty-manifold-fixtures -- diff --check
```

Optional adapter probes stay outside the core crates. QCL-081 LSL broker
evidence can be emitted when the local Python environment has `pylsl/liblsl`:

```powershell
python tools\qcl081_lsl_clocked_samples.py --json --source manifold-lsl-broker --sample-count 16
```
