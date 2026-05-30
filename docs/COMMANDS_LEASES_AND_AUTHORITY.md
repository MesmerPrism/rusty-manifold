# Commands, Leases, And Authority

Every mutating command is a request to Manifold authority.

## Command Envelope

A command envelope should include:

- command id and name;
- target id and scope;
- input schema id;
- expected graph or registry revision when applicable;
- required capability;
- required lease scope when exclusive;
- preconditions;
- safety class;
- operator-confirmation requirement;
- request timestamp and holder identity.

## Result

Every command produces either an acknowledgement or a rejection. Rejections must
be machine-readable and safe for clients, tools, and UI surfaces to display.

## Lease Rules

Leases are scoped, expiring, and revision-aware. A UI, API client, tool, or
automation may request a lease, but only Manifold authority accepts, renews,
releases, or rejects it.
