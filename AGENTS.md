# Instructions for coding agents

Sameroot is a peer-to-peer database. The code is in Rust.
Read [README.md](README.md) and [docs/vision.md](docs/vision.md) first.
The design decisions are in [docs/design](docs/design).

## Language

- Write all text in English. This includes code, documents, commit messages, pull
  requests, and your answers.
- Obey ASD-STE100 Simplified Technical English in instructions and in your answers.
- These are the primary rules of ASD-STE100:
  - Write short sentences. Use a maximum of 20 words in an instruction and 25 words in a
    description.
  - Write one instruction in each sentence.
  - Use the active voice.
  - Use simple verb tenses.
  - Use one word for one meaning. Do not use a different word for the same thing.
  - Write a maximum of six sentences in each paragraph.
  - Use a vertical list for complex text.
- The terms of the project are technical names, and you can use them. Examples: ledger,
  Merkle root, void, succession.

## Code

- Do not write comments in code.
- Give each variable, function, type, and module a name that shows its purpose clearly.
- If the code is not clear without a comment, change the names or the structure.
- Do not remove the comments that the code has now in one large change. Remove them only
  in the part of the code that you change.
- Documentation comments (`///` and `//!`) on public items stay. The build fails without
  them.

## Contents of this repository

- Put these items here: source code, tests, conformance vectors, the specification,
  design documents, and documentation for users and operators.
- Do not put these items here: plans, strategy, announcement drafts, review notes,
  discussion logs, and other work documents.
- If a task makes such a document, give it to the maintainer. Do not commit it.
- Do not add personal host names, addresses, key material, or the identifiers and invites
  of live databases.
- Use `example.org` and temporary databases in examples.

## Procedure

- A change to the format, the protocol, or the rules language starts as a design document
  in `docs/design`.
- Do not make the conformance vectors in `vectors/` again to make a test pass.
- Report security problems as [SECURITY.md](SECURITY.md) tells you. Do not open a public
  issue for them.
- Make sure that these commands are successful before you open a pull request:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
