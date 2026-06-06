# Hosts And Deployment

Host manifests advertise where Manifold surfaces are available. Deployment
manifests describe selected placement and launch intent.

## Endpoint Visibility

- `loopback`: local-only endpoint.
- `paired_lan`: explicitly paired local-network endpoint.
- `public_relay`: externally managed relay endpoint.

Endpoint selection does not grant mutation authority. Mutating commands still
require role, capability, lease, expected revision, holder identity, expiry,
and any required operator confirmation.

## Host Manifest Authority

Host manifests are accepted state. Clients may propose changes with
`ManifoldHostManifestChangeRequest`, but Manifold authority accepts or rejects
the proposal against the current authority revision, host-manifest lease,
review clock, capability set, endpoint security policy, active leases, command
descriptors, and module runtime backends. A host-manifest lease that has
expired at the review clock is rejected even if it is still present in
accepted authority state.

The review surface is source-only. It accepts or rejects JSON contract state and
emits `ManifoldHostManifestAuthorityReview` plus a matching audit event. It
does not probe permissions, open endpoints, start host services, or call
platform adapters.

Accepted reviews become accepted authority state only through a
`ManifoldHostManifestAuthorityApplication` receipt. The receipt advances the
authority revision and installs the accepted host manifest in the authority
snapshot. Rejected reviews produce a
`ManifoldAuthoritySnapshotApplicationRejection` and leave accepted state
unchanged.

Application is still source-only. It does not probe permissions, open
endpoints, start services, contact Hostess, or call platform adapters.

## Deployment Records

Deployment manifests should capture:

- selected host ids;
- selected package and graph versions;
- adapter placement;
- endpoint and security policy;
- launch and recovery profile;
- artifact and session-output policy.

## Platform Host Contract Fixtures

The current contract fixtures include generic host categories only:

- `desktop.local`
- `mobile.device`
- `headset.device`

These fixtures describe available backends, permissions, endpoint visibility,
and lifecycle limits. They do not add platform SDK dependencies or imply
device-specific authority.
