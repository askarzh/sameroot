# Encrypted values

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §15.

To specify:

- Envelope format and suite field; HPKE base mode per recipient
- Key commitment
- Chunked AEAD for large values
- AAD binding: db, subspace, path, signer

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
