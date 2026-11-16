# Identities and signatures

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §6.

To specify:

- Public key encoding and the display string
- Strict Ed25519 verification: canonical S, canonical key and R encodings, small-order rejection, no batch verification
- Signatures over typed ids
- Encryption keys and endpoint bindings (published in cards, §10 of this spec)

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
