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

## GUI And CLI Parity

A GUI control is not the first or only command surface. For every mutating GUI
action:

1. define the command descriptor, input schema, capability, lease scope,
   preconditions, safety class, and acknowledgement or rejection shape;
2. implement the command once in a non-UI path;
3. expose a CLI command that calls that same implementation;
4. make the GUI call that same implementation instead of duplicating logic;
5. test the command through the CLI or command API before judging the GUI.

CLI output must be machine-readable enough for agents to assert accepted,
rejected, issue code, revision, lease, and target state. Manual GUI testing is
for usability, focus, layout, and interaction quality, not for proving command
semantics.

Purely presentational local UI state, such as a collapsed panel or local theme
preview, does not need CLI parity unless it changes persisted state, runtime
state, package state, deployment state, or session evidence.

## Lease Rules

Leases are scoped, expiring, and revision-aware. A UI, API client, tool, or
automation may request a lease, but only Manifold authority accepts, renews,
releases, or rejects it.
