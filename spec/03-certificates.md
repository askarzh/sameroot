# Delegation certificates and voids

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §7.

To specify:

- Certificate fields, size and depth limits
- Chain validation: conjunction of every link's area and window
- Certificates as dependency blocks; the leaf id in entries
- Voids: format, who may sign, the grow-only set and its effect

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
