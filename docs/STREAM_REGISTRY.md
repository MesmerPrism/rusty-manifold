# Stream Registry

The stream registry is a revisioned view of available streams and their
topology.

## Stream Manifest

Stream manifests should describe:

- stream id and semantic family;
- sample header and schema id;
- source module id;
- rate class;
- timestamp domains;
- retention and replay policy;
- sensitivity level;
- transport offers;
- subscription policy;
- compatibility hints.

## Registry Snapshot

A registry snapshot records one accepted topology revision. It should be
diffable and safe for read-only clients to render without becoming authority.
