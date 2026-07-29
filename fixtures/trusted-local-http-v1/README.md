# Trusted Local HTTP v1 Manifold fixture

This directory is an additive conformance fixture for the
`trusted_local_http_v1` Quest adapter profile and the platform-neutral
`rusty-manifold-local-control` authority composition. It does not define a
transport, listener, pairing-code implementation, or player runtime.

The fixture maps the adapter into typed Manifold contracts:

- local-control starts disabled and accepts only a wearer-opened, bounded
  pairing window;
- admission binds the real signed Quest adapter identity, issues a short-lived
  opaque session token, and consumes one-use capability request ids;
- a separate non-secret logical id represents the paired browser controller;
- control-lease review/application admits at most one active controller for
  the player scope;
- command review and Runtime Host application preserve expected revisions,
  request causality, replay protection, expiry, and revocation;
- WebSocket acknowledgement and Manifold `command_accepted` are not evidence
  that the Quest player changed state;
- Quest alone emits downstream `command_applied` after a Media3/ExoPlayer
  callback and advances the effective player-state revision.

The manual address and single-use pairing code are adapter evidence. They may
justify an admission request, but they do not mint a session, lease, or command
acceptance. The code itself, opaque session tokens, passwords, device-management
credentials, production opaque session tokens, and other secrets are
intentionally absent from these public fixtures. Token-shaped values used for
contract conformance are synthetic and are not credentials.

`valid-flow.json` is a synthetic source-only flow. `damaged-mappings.json`
enumerates fail-closed cases. `contract-map.json` binds each reused concern to
an existing repository fixture and schema id. `local-control-policy.json`,
`controller-evidence.json`, `command-request.json`, and `safe-status.json`
exercise the strict public composite contracts.

Run the focused validator from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\fixtures\trusted-local-http-v1\Test-TrustedLocalHttpV1Fixtures.ps1
```

The validator opens no socket and has no external dependencies.

## Identity boundary

A browser does not claim or fabricate a platform signing identity. The
`ManifoldClientIdentity` is the installed Quest adapter's real package and
signing-certificate identity. Pairing evidence separately binds the logical
browser controller id to the current wearer-opened window. The Quest adapter
must remain fail-closed until its mandatory single-use code evidence is
converted into an accepted composite Manifold admission receipt. QR may convey
the same code as a convenience, but never replaces it. No adapter-local
fallback admission is permitted.
