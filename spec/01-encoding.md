# Encoding and hashing

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §5.

To specify:

- The CBOR profile: allowed major types, text-only map keys and their order, integer range, definite lengths, no tags or floats, duplicate and trailing-byte rejection, depth limit
- The re-encode-and-compare rule for every decoder
- BLAKE3-256 derive-key contexts per object type, and the typed-id construction
- Digest and CID string forms (display and export only)

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
