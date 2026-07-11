# Licensing

Project-owned Rusty Manifold source code is licensed under
`AGPL-3.0-or-later`. See `LICENSE` for the GNU Affero General Public License
version 3 text.

Third-party dependencies, generated artifacts, fixtures imported from other
projects, binary releases, captured data, and external tools keep their own
licenses and provenance requirements. Do not assume they are covered by this
repository license.

Before distributing binaries or hosted services, generate third-party notices
and record the source commit, dependency report, release artifact hashes, and
source availability path.

The peer-enrollment verifier pins `ed25519-dalek` 2.1.1 (BSD-3-Clause) because
that release supports the workspace Rust 1.80 floor. Direct SHA-256 use is
provided by `sha2` 0.10 (MIT OR Apache-2.0). Their transitive
cryptographic dependencies retain their declared licenses and must appear in
the generated third-party notice for distributed binaries.
