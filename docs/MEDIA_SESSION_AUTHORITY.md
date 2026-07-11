# Media Session Authority

Manifold owns the accepted low-rate session and stream references. The
`rusty.manifold.media.session_descriptor.v1` contract binds an accepted
authority revision to source, processor, route, sink, stream, and platform
runtime-spec identities. It contains no frames, packets, camera settings,
codec buffers, socket handles, or application policy.

High-rate payloads remain on the `binary-media` data plane. Quest or another
platform runtime may adopt an accepted descriptor and report its own
receiver-first lifecycle, but that adapter must preserve the Manifold decision
id/revision and must not relabel platform readiness as accepted session state.

Remote-camera compatibility is an explicit descriptor flag. It permits a
legacy contract to project into the generic runtime; it does not make camera
defaults, permissions, properties, or command names generic.

Validation:

```powershell
cargo test -p rusty-manifold-model media_session
```

Canonical and damaged fixtures live under `fixtures/media-session/` and
`fixtures/damaged/media-session-*.json`.
