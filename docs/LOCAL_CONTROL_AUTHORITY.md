# Local Control Authority

`rusty-manifold-local-control` is the platform-neutral authority composition
for a short-lived local control surface. It owns the Manifold decisions needed
to admit one browser controller, issue and revoke its admission token,
hold one controller lease, accept only registered commands, reject replay,
enforce rate/session/idle limits, and expose a display-safe status.

It does not open HTTP or WebSocket listeners, discover peers, render a web UI,
verify plaintext pairing-code material, inspect Android packages, or execute
player effects. Those are downstream adapter/application responsibilities.

## Identity boundary

Browser pairing does not invent a platform signer. The
`ManifoldClientIdentity` in `ManifoldLocalControlPolicy.adapter_identity` is
the real installed Quest adapter package and signing-certificate identity. The
admission grant and opaque token remain bound to that verified adapter.

`controller_id` is a distinct non-secret logical identifier for the browser
controller proven inside the current bounded window. Paired-mode evidence binds
the trusted adapter id, exact window id, logical controller id, presentation
method, verification result, and bounded observation lifetime. It never
contains the code. Manual code entry is always supported; QR presentation is
only a convenience for conveying the same mandatory single-use code.

An additive `open_lan_insecure` access mode carries different evidence: an
explicit foreground wearer action, or an explicitly policy-enabled Android
debug-shell action, opens the bounded window and the first LAN peer may claim
the sole controller lease without a code. Its evidence must say
`open_lan_insecure` and `pairing_code_verified=false`; it can never be reported
as pairing. Manifold still owns admission, the one lease, command review,
replay, expiry, and revocation. Debug-shell enable is rejected unless the
packaged policy explicitly opts in, and downstream products must expose that
route only from a shell-UID-gated debug component.

## Lifecycle

Construction is disabled. The wearer first authorizes
`open_pairing_window`, which changes source authority state but does not open a
socket and returns a typed window receipt carrying request id, window id,
resulting revision tuple, safe status, and rejection. `admit_controller` then
atomically composes:

1. a short-lived adapter-bound admission token;
2. a single logical-controller lease in generic Manifold authority; and
3. the exact lease adoption in Runtime Host.

`accept_command` consumes one request id, authorizes the command capability,
and reviews/applies the exact registered Runtime Host command. The composite
receipt says `command_accepted` and always sets
`proves_application_effect = false`. A downstream Quest player owner must
derive `command_applied` and the effective player-state revision from
Media3/ExoPlayer callbacks, retaining the composite receipt id and request
causality.

The composite `local_revision` is the browser concurrency token. One owner
mutex encloses the admission, generic lease, and Runtime Host snapshots. Every
committed lower-authority revision change advances `local_revision`; notably,
an admitted capability use followed by Runtime Host rejection still advances
the composite revision. The adapter may therefore validate one browser
`expected_authority_revision`, then construct the strict internal request from
the retained exact revision tuple under the same lock. It must not read or fill
the lower revisions outside that checked critical section. Receipts and safe
status expose the lossless local/admission/lease/host tuple.

`revoke_controller` uses retained authority, not client impersonation, to
revoke the admission token, terminally revoke the generic lease, and remove
the Runtime Host lease. `expire_controller` runs only on an explicit trusted
clock request and enforces session or idle expiry through that same terminal
revocation chain. Successful revocation returns the source authority to the
disabled state, so another window requires a new wearer action and new code.
`disable` also closes an unadmitted pairing window, so wearer cancellation or
listener-start failure cannot leave the source authority claiming it is open.
When a controller is active, `disable` routes through the same full terminal
revocation chain.

## Closed command surface

The immutable build-time registry binds each command id to:

- one admission capability;
- the one controller lease scope for mutating commands;
- an exact typed-parameter contract, or no parameters; and
- a bounded Manifold safety class.

Unknown commands and mismatched typed parameters fail before Runtime Host.
There is no generic execution route and no shell, ADB, intent, component,
path, URL, plugin, upload, runtime JavaScript, or MCP command contract.

The public video example uses this exact mapping:

| UI command | Dotted command id | Typed parameters |
|---|---|---|
| `describe` | `command.player.describe` | none |
| `get_state` | `command.player.get_state` | none |
| `list_videos` | `command.player.list_videos` | none |
| `pause` | `command.player.pause` | none |
| `play` | `command.player.play` | none |
| `select_video` | `command.player.select_video` | `params.player.video_selection` digest |

The top command receipt exposes the exact selected controller lease id. Player
expected-revision and no-op decisions remain Quest-owned preconditions; they
are not Manifold player state.

## Transport security

The intended `trusted_local_http_v1` adapter uses same-origin packaged assets,
exact Host/Origin checks, a manual address plus single-use pairing code, and a
short foreground listener window. Authentication is suitable only for a
trusted LAN or private hotspot. Plain HTTP/WebSocket provides no
confidentiality. Passwords, private evidence, Fleet/device-management
credentials, and other secrets must never cross this profile.

The separately labelled Open LAN mode removes authentication as well as
confidentiality: any peer on the reachable network may request the single
controller lease until expiry or on-headset revoke. Discovery advertisements
may contain only non-secret service metadata and must never contain the pairing
code or a bearer token.

The locked Rust provider owns trusted clock snapshot/sequence construction and
the 256-bit admission-token entropy. Java wall time or handler wakeups are
observation inputs, not authority clocks. The adapter's CSPRNG owns the
single-use human pairing code and its exact evidence. If an HTTP cookie cannot
carry the dotted Manifold token id, the adapter may issue a separate opaque
cookie and retain a closed one-to-one server-side map to the exact token for
the session; it must not reinterpret cookie text as a command or identity.

## Public API

- `ManifoldLocalControlAuthority::new`
- `open_pairing_window` → `ManifoldLocalControlWindowReceipt`
- `admit_controller`
- `accept_command`
- `revoke_controller`
- `expire_controller`
- `disable`
- `safe_status`

Requests use strict `deny_unknown_fields` decoding and exact expected
revisions. Composite receipts have deterministic
`receipt.local_control.<operation>.<request_id>` identities and retain their
typed lower-authority receipts. `ManifoldLocalControlSafeStatus` exposes only
coarse state, public ids, revisions, deadlines, and the last accepted command
receipt id; it omits bearer and signing material.
