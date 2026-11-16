# Genesis and rules

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §9.

To specify:

- Genesis fields, nonce, DatabaseId
- The rule language (Sameroot Logic, language 1): operators, types, evaluation budget, no coercion
- Rule inputs: genesis, header, verified-chain facts — and nothing else
- Presets and their compiled rules
- Limits in consensus; what stays local policy

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
