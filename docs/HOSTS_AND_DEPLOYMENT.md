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
