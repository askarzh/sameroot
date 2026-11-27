# Notes for coding agents

Sameroot is a peer-to-peer database in Rust. Start with [README.md](README.md) and
[docs/vision.md](docs/vision.md). Design decisions are in [docs/design](docs/design).

## What belongs in this repository

- Source, tests, conformance vectors, the specification, design documents, and
  documentation for users and operators.
- Not here: plans, strategy, announcement drafts, review notes, discussion logs and
  other working documents. They are kept outside this repository. If a task produces
  one, hand it to the maintainer instead of committing it.
- Never add personal host names, addresses, key material, or the ids and invites of
  anyone's live databases. Use `example.org` and throwaway databases in examples.

## Working rules

- A change to the format, the protocol or the rules language starts as a design
  document in `docs/design`, not as code.
- Conformance vectors in `vectors/` are never regenerated to make a test pass.
- Code comments, commit messages and pull request text are in English.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.
- Before a pull request, these must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
