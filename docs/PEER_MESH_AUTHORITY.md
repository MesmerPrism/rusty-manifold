# N-Peer Mesh Authority

`rusty-manifold-peer` owns bounded low-rate mesh membership for three to 32
accepted peers. Adapters propose a unique sorted member set and bounded route
candidates; only Manifold advances membership revision, elects the canonical
lowest peer id as coordinator, ranks authenticated direct routes, records
audit, expires stale members, and retains explicit revocation against replay.

Direct route ranking is deterministic: latency, hop count, then candidate id.
The bounded direct-plus-advisory candidate graph must connect the member set.
Only ranked authenticated direct pairs enter `selected_routes` and may be
marked eligible for a direct media lane; separate peer/media admission and the
referenced direct-P2P socket provider remain required. Advisory gossip is
status-only, cannot authenticate a direct route, and never carries media.

Eligibility is not a lease. The direct-lane lease authority described in
`PEER_ENROLLMENT_AND_DIRECT_LEASE_AUTHORITY.md` binds a selected route to the
current mesh revision, a signed peer-session topology authorization, an exact
pair, and optionally an accepted generic media-session reference. Only that
revisioned receipt authorizes later platform adoption.

Same-epoch coordinator disagreement is split brain and rejects without revision
change. Older epochs, proposal replay, stale observations, disconnected graphs,
revoked-member resurrection, and advisory-to-media substitution also fail
closed. The existing two-peer session authority remains unchanged.

Validate with `cargo test -p rusty-manifold-peer`.
