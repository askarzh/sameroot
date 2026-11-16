# Ordering, deletes and retention

Status: **skeleton**. Until this file is written, the normative source is
[docs/design/0001-architecture.md](../docs/design/0001-architecture.md) §8.2, §10.

To specify:

- Last-writer-wins on (ts, EntryId) per (subspace, path)
- delete and deletePrefix semantics
- Future-timestamp deferral (local admission, not consensus)
- Expiring databases (maxTtl, exp, tombstone dropping) and permanent databases
- Succession: predecessor field and forward record

Every rule here gets conformance vectors in [`vectors/`](../vectors/).
