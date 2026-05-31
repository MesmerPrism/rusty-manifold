# Supply Chain

Manifold package and adapter metadata should make release risk visible.

## Required Metadata

- Package id and version.
- Source and provenance.
- `provenance_refs` that point to package-owned provenance manifests before
  runtime code is ported.
- SPDX license expression.
- Dependency and third-party notice requirements.
- `notice_refs` for publication, affiliation, medical, generated asset, or
  other package-specific notices.
- Native, unsafe, network, subprocess, device, filesystem, model-asset, and
  binary-payload flags.
- Validation commands and fixture set.
- Public/private release status.

Core crates should avoid large optional SDKs behind feature flags. Prefer
separate adapter crates, tools, examples, or downstream products.
