# Trusted Local HTTP v1 Manifold fixture

This directory is an additive conformance fixture for the
`trusted_local_http_v1` Quest adapter profile. It does not define a transport,
listener, pairing-code implementation, player runtime, or new Manifold
authority.

The fixture maps the adapter into existing Manifold contracts:

- admission issues a short-lived opaque session token and consumes one-use
  capability request ids;
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
an existing repository fixture and schema id.

Run the focused validator from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\fixtures\trusted-local-http-v1\Test-TrustedLocalHttpV1Fixtures.ps1
```

The validator opens no socket and has no external dependencies.

## Boundary and limitation

The existing admission fixture family is signature-scoped and does not define
how a browser proves a stable platform identity. This fixture therefore starts
at a deployment-projected synthetic controller identity and proves reuse from
the Manifold admission decision onward. The Quest adapter must remain
fail-closed until its manual pairing evidence is converted into an accepted
Manifold admission receipt. No adapter-local fallback admission is permitted.
