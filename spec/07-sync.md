# Replication protocol

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §12.

To specify:

- Handshake: versions, fingerprint version, limits
- The reconciled set and item hints
- Range-based reconciliation rounds; fingerprint version 1 (per-session keyed sum)
- Dependencies: certificates and voids; values inline and by reference
- Live updates; snapshot semantics
- Resource limits and the negative cache

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
