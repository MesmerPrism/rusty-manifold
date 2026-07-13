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

`rusty-manifold-media-session` closes packaging around that descriptor. Its
`rusty.manifold.media.session_product_binding.v1` document retains the exact
typed descriptor plus `sha256:<hex>` of canonical typed JSON. Reference arrays
must be strict sorted sets. A product may not substitute a reordered,
digest-damaged, or merely shape-compatible descriptor after packaging.

The product binding still owns no platform effect. Manifold command acceptance
authorizes a referenced action; the Quest product runtime separately proves
receiver readiness, source start, stop, and cleanup. An Android/Java response
must not infer platform completion from this descriptor or from command
acceptance.

The accepted media client grant keeps outer broker provenance and app
provenance separate. It binds the broker adapter/Runtime Host, semantic product
fingerprint, exact packaged product-lock SHA-256, outer command and lease,
signature-projected client, packaged client-lock id/SHA-256, admission grant,
and the app's own feature-lock id/SHA-256. A client-lock digest cannot stand in
for the app feature lock. The peer Runtime Host mints the inner media lease only
by atomically executing the owning live `ManifoldBrokerRuntime`; caller-created
or deserialized mutation receipts are never lease authority.

Validation:

```powershell
cargo test -p rusty-manifold-model media_session
cargo test -p rusty-manifold-media-session
cargo run -p rusty-manifold-media-session --bin media_session_digest -- fixtures/media-session/generic-media-session.pass.json
```

Canonical and damaged fixtures live under `fixtures/media-session/` and
`fixtures/damaged/media-session-*.json`.
