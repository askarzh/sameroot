# Conformance vectors

Language-neutral test vectors for format 1. A second implementation is conformant
when it agrees with every vector.

Rules:

- One JSON file per topic (`encoding`, `identities`, `certificates`, `entries`,
  `rules`, `ordering`, `retention`, `sync`, `admission`, `encryption`), each case
  with an `id`, a description, the inputs, and the expected output or error.
- Binary values are lowercase hex.
- **Vectors are generated once by the reference implementation, reviewed, and checked
  in. They are never regenerated to make a failing test pass:** a failing vector
  means the code changed the format.
- Edge cases are as important as the happy path: non-canonical encodings, Ed25519
  small-order and non-canonical inputs, limits off by one, rules at their budget.

Files: `core.json` (format 1 as of design 0003) and `0004.json` (the design 0004
additions: work, voids with keep lists, key voids, forwards, the genesis succession
fields, the reference index and the ledger commitment), and `seal.json` (the
application-level sealed values and hidden names of `sameroot-seal`: memory written
today must stay readable).
