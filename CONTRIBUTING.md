# Contributing

Thanks for looking. Sameroot is an experimental prototype with one maintainer.

- **Issues are welcome:** bugs, questions, and ideas. Include the commit, platform, and
  what you ran.
- **Discuss before a pull request** of any size, especially one touching the format,
  the protocol or the rules language. Those are still changing, and design decisions
  are written down in [docs/design](docs/design) first.
- **Checks:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, and `cargo test --workspace` must pass. Conformance vectors in `vectors/`
  are never regenerated to make a test pass.
- **Security problems** go through [SECURITY.md](SECURITY.md), not public issues.

The format may break before it's frozen. Upgrades may then need new databases.

By contributing you agree to license your work under the MIT license of this repository.
