# Pair media route authority

Manifold can retain a directional media route grant for the two peers in one
current signed peer session. This authority belongs to `rusty-manifold-peer`
and is composed durably by `rusty-manifold-peer-runtime-host`. It does not
depend on `ManifoldPeerMeshState`, change the three-peer mesh minimum, or
change existing direct-lane lease contracts.

An issue request names one versioned route leg, a retained peer session, and a
retained accepted media decision. Review joins those references to current
peer status, enrollment, rendezvous signatures, signed topology, the accepted
media descriptor, the exact current Runtime Host lease expiry, an accepted
Runtime Host command, and the immutable media client grant. The retained
record keeps these identities separate:

- source peer and sink peer, with their signed topology roles;
- media client/requester and its Runtime Host lease;
- Manifold Runtime Host authority identity and provider epoch;
- accepted media runtime specification and exact resource subset.

The authority host and provider epoch prove who made and retains the Manifold
decision. They do not identify or attest a codec, renderer, camera, relay, or
transport effect provider. A deployment adapter must bind a current grant to
its own effect-provider instance and return deployment-verified cleanup
evidence before claiming a live route.

The state has explicit caps of 4,096 retained routes, 8,192 consumed request
identities, and 4,096 cleanup receipts. Issue, stop, revoke, expiry, replacement,
and cleanup reject a regressing authority clock. Replacing a leg preserves the
old record as `superseded` with cleanup pending. Stop, revoke, and expiry also
retain terminal records until cleanup is acknowledged. Restart validates the
complete retained state, host audit closure, deterministic Runtime Host
dispatch/application identities, typed request digests, runtime revisions, and
replay guards. Accepted stop, revoke, and cleanup records retain their command,
requester, lease, media scope, request id, typed digest, and resulting Runtime
Host revision.

Admission reserves one future stop or revoke and one cleanup for each current
grant, plus cleanup for every terminal pending grant. Runtime Host composition
reserves the same obligations inside its audit sequence and embedded Runtime
Host request, audit, and revision caps, so another authority operation cannot
consume their capacity. A provider epoch cannot roll over while any current or
cleanup-pending pair grant remains. Capacity reservation does not issue or
renew a lease. Stop remains route-client authority, revoke remains trusted
media-revoker authority, and cleanup accepts either the route client or an
existing trusted media revoker with an exact current media-scope Runtime Host
lease. This lets a longer-lived trusted operator close delayed cleanup after
the original route-client lease expires.

Peer Runtime Host snapshot v4 introduced the Wi-Fi pair-route state. The active
v5 snapshot wraps that state into the mixed v2 authority without changing any
legacy record bytes, counters, replay ids, or cleanup evidence. The explicit
v1, v2, and v3 readers preserve the legacy embedded Runtime Host command
registry and initialize an empty route state; legacy input containing any pair
command is rejected because those versions never owned that authority. A v5
product opts in by registering the complete four-command pair bundle under the
existing media authority lease scope. An exact media command set without that
bundle is valid only with empty pair state. Partial bundles and wrong scopes
fail closed. The active v5 field has no serde default.

Removing the third member from an existing mesh can close that mesh and make
mesh-backed direct-lane leases stale. It does not widen or revoke an independent
pair route. Pair-route validation continues to recheck its own signed session,
topology, accepted media decision, provider epoch, and expiry. A live topology
must exactly equal the route's retained issuance topology. Peer revocation
removes the live topology but does not erase that issuance evidence. A retained
`current` lifecycle label is therefore never sufficient live authority after
the peer session or source media decision stops, expires, or is superseded.
Snapshot restore still admits that retained obligation so it can be
terminalized and cleaned up.

The host tests cover issue without a mesh, both route directions, replay,
replacement, cleanup by a longer-lived operator lease, expiry at the original
client-lease boundary, operator revocation, damage rejection, exact legacy
migration, command-bundle opt-in, and an explicit three-to-two mesh transition.
Restart coverage also proves terminalization and cleanup remain reachable after
source media stop, expiry, supersession, or peer-session revocation. Device and
transport behavior remain outside this host-only contract and require later
two-device acceptance.

## Mixed Wi-Fi Direct and common-LAN authority

The Common-LAN reciprocal context permits at most 240 seconds between its
signed issue and expiry times. A Common-LAN pair route permits at most 180
seconds from route issue. Wi-Fi Direct retains its 120-second reciprocal and
route ceilings. These are maximums, not automatic grants: a route still ends
at the earliest peer-session, signed-topology, accepted-media, or Runtime Host
lease expiry. Current-route readback rechecks those identities and times.

The 180-second route ceiling budgets a 110-second rendered-frame qualification
and at most 70 seconds combined for delay after route issue, Start, reconnect,
and initiating terminal action while the route remains current. Retained
cleanup may continue after a route stops being current; this ceiling does not
prove cleanup completion. The longer signed-context window leaves room for
pairing and route setup: the observed short-window client had only 111.75
seconds remaining immediately after pairing, before route issue or Start.
That is the only measured timing here. The consumer must measure actual Start,
reconnect, and cleanup times and choose shorter expiries where possible.
Longer signed authority increases the maximum time a still-current enrolled
peer can present the same accepted session; signature, nonce/replay, revocation,
credential, topology, lease, and exact route-lineage checks remain required.

The active v2 route state is a closed tagged union over the unchanged Wi-Fi
Direct v1 record and a common-LAN record. Both variants consume one shared
authority revision, replay set, clock, route cap, and reserved terminal and
cleanup capacity. A common-LAN record retains the complete signed topology,
two advertised listening endpoints, transport and packaged-configuration
digest, accepted media decision, client grant, and Runtime Host
command/dispatch/application proof. Current readback rechecks those retained
values against the actual current peer session, signed topology, accepted
media record, provider epoch, direction, and descriptor resource subset.

The v1 issue, stop, revoke, current, and cleanup APIs and signing bytes remain
valid for Wi-Fi Direct. Explicit compatibility entry points apply v1 terminal
commands to a Wi-Fi record in mixed v2 state without changing their typed
parameter digest. They cannot target a common-LAN record. New common-LAN
commands use the v2 tagged request and digest. Cleanup may be completed by the
original current client or by a trusted revoker carrying its own current
media-scope command lease; the expired issue lease remains provenance rather
than a cleanup prerequisite.

Broker lease-revocation convergence terminalizes every still-current route
that names a revoked accepted-media decision in one shared route-authority
mutation. It retains the authenticated convergence identity and marks cleanup
pending without inventing a Runtime Host command receipt. Snapshot restore
must join that source identity to the retained applied Broker convergence;
explicit client stop and operator revoke continue to require their exact
Runtime Host command bindings. A fresh trusted revoker lease may then complete
the retained cleanup obligation after the original media lease has expired or
been released.
