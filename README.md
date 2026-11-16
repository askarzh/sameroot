# Sameroot

**Shared memory for your devices and AI agents, kept like a ledger. Every node holds
the same signed records, and one fingerprint (a Merkle root) shows they match. No
central server, no blockchain.**

Sameroot is a peer-to-peer database platform. Each database is a set of signed
records that every participant keeps a copy of. Rules fixed when the database is
created say who may write what, and every node enforces them. The current value of a
key is computed from the records. The first application is a shared memory for AI
agents: Claude Code, Codex and Antigravity on different machines read and write one
memory, encrypted with the owner's key. The name says the idea: nodes with the same
root hold the same memory.

> **Experimental.** A working prototype, running on four machines: two cloud servers,
> a box behind NAT, and a laptop on a corporate network that reaches the others through
> a relay. It has had no independent security review. The format isn't frozen: an
> upgrade may need new databases. Anyone who knows a database's id can read its
> metadata; see the [threat model](docs/threat-model.md).

![Three live nodes, one fingerprint: a node offline and catching up, agents with keys of their own, a leaked key revoked, and a succession](docs/media/ledger-demo.gif)

[MP4](docs/media/ledger-demo.mp4) · 2 min, recorded on the live mesh. The colour of
each card is its node's fingerprint, so the same colour means the same records.
1. Writes from three machines arrive everywhere.
2. A node goes offline and catches up in 6 s.
3. Two agents write with keys of their own.
4. One agent's key leaks and is revoked: its later writes lose their effect, and its
   earlier note comes back.
5. The owner starts a successor that carries the state and renews every device's
   certificate. The nodes follow on their own, and the old database shrinks to a stub.

## How it works

- **A database is a set of signed records, not a chain.** A blockchain keeps records
  in one agreed order, each block linked to the one before. Here a record is simply
  in the set or not, and the order it arrived in doesn't matter. Nodes don't vote or
  mine: they only have to end up with the same set.
- **One fingerprint shows that two nodes match.** Each node computes a short
  fingerprint of everything it holds: the root of a Merkle tree over the records.
  The same fingerprint means the same records. When fingerprints differ, the nodes
  compare the tree branch by branch and fetch only what is missing, so a node that
  was offline catches up in seconds instead of replaying a history.
- **Rules every node enforces.** The database's genesis fixes who may write where
  (`access`), what a valid record is (`validity`), and how the current state is
  computed (`resolution`, e.g. last writer wins). A record that breaks the rules is
  refused by every node, so nodes don't have to trust each other.
- **Nothing is rewritten.** A delete, a negation (undo one write) or a revocation (a
  leaked key) is a new record, and the state is computed from all of them. A database
  that has grown too long is replaced by a successor that carries the current state,
  and the old one shrinks to a small stub that points to it.

Records travel over [iroh](https://iroh.computer) (QUIC, with NAT traversal and
relays). Values travel separately, by their hash, through
[iroh-blobs](https://github.com/n0-computer/iroh-blobs). The platform itself is open:
any node serves what it holds to anyone who knows the database id. Privacy belongs to
the application, so the agent memory encrypts its values and hides its key names.

### Why not git, a CRDT or Syncthing?

- **Git** keeps a chain of commits, and merging is a person's job; in practice there
  is a central remote.
- **Syncthing** copies files, with no rules about who may write what.
- **A CRDT** is the closest relative: the ledger is a grow-only set that converges on
  its own. Sameroot adds three things on top:
  - a signature on every record;
  - rules for writing that every replica enforces;
  - a fingerprint that proves two replicas hold the same set, with short proofs that
    a record is in it or absent from it.

## What it is not

- **No transactions, no global order, no finality.** A late record can still change a
  value until every node has it. Every node then computes the same result, but there
  is no moment when a write is final. That suits shared knowledge, memory and
  coordination; it doesn't suit money or unique names.
- **Metadata is public.** Values are encrypted by the application. Signer keys,
  timestamps and value sizes are visible to anyone who holds the database. Key names
  are visible too, unless the application hides them, as the agent memory does.
- **Revoking a key stops its writes from counting.** It doesn't take back what the
  holder could already read. A leaked memory key means re-encrypting under a new one,
  and key rotation at succession isn't built yet.
- **A prototype:**
  - one implementation;
  - a specification still in outline;
  - a format that may change before it's frozen;
  - builds from source only, tested on Linux (x86-64 and arm64) and macOS.

## Try it

Prebuilt binaries for Linux (x86-64, arm64) and macOS (Apple Silicon) are on the
releases page. Or build from source (Rust 1.91 or later):

```bash
cargo build --release -p samerootd -p sameroot -p sameroot-mcp
target/release/samerootd &                       # machine A: the node (state in ~/.sameroot)
target/release/sameroot owner init               # the owner key, kept outside the node
target/release/sameroot owner create-db notes    # a database; this node may write in it
target/release/sameroot put notes/hello "hi"
target/release/sameroot invite                   # → sameroot:join?v=1&db=…&id=…
```

```bash
target/release/samerootd &                       # machine B
target/release/sameroot join 'sameroot:join?v=1&db=…'
target/release/sameroot list                     # A's note, signed by A's device
target/release/sameroot status                   # the same fingerprint as on A
```

`scripts/milestone-local.sh` runs a two-node scenario on one machine.

**Shared memory for your agents:**

```bash
target/release/sameroot-mcp keygen               # the memory key; copy it to your other devices with scp
claude mcp add --scope user sameroot -e SAMEROOT_DB=<db> -e SAMEROOT_AGENT=claude \
  -- $PWD/target/release/sameroot-mcp
```

Codex and Antigravity are registered the same way; see [docs/mcp.md](docs/mcp.md).
With `SAMEROOT_AGENT` each agent signs with a key of its own, so one agent can be
revoked without the others.

[docs/operations.md](docs/operations.md) covers the rest:
- running more devices;
- revoking a lost device or a leaked agent key;
- moving to a successor database and collecting the old one;
- relays and services.

## What works

- **The ledger** ([design 0003](docs/design/0003-ledger.md)): a 16-ary sparse Merkle
  trie keyed by record id. Proofs of inclusion and of absence are about 700 bytes
  for a million records.
- **The rules:** `access` and `validity` programs in Sameroot Logic 1 (strict,
  bounded, an error denies), and a resolution rule (`lww`, `earliest`,
  `collection`). Deletion and negation are records.
- **Signed records:** Ed25519, canonical CBOR, BLAKE3. Delegation certificates
  connect the owner, devices and agents.
- **Authority and succession** ([design 0004](docs/design/0004-authority-and-succession.md)):
  - per-agent keys;
  - revocation that keeps what a node saw before a leak and drops what came after;
  - a proof-of-work field for open-write databases;
  - a reference index in the root, so the absence of a revocation or a negation can be
    proven;
  - succession: rewrite mode, with nodes following on their own, a late-write inbox,
    and collection down to a stub.
- **Replication** over iroh:
  - fresh records are pushed at once;
  - an offline node catches up by comparing trees;
  - values stream by hash, verified as they arrive, and small ones ride inline.
- **Shared memory for agents** ([docs/mcp.md](docs/mcp.md)): an MCP server for
  Claude Code, Codex, Antigravity or any MCP client, with values encrypted and key
  names hidden.
- **Operations:** systemd user services, a LaunchAgent on macOS, and a relay of our
  own for networks that allow only TCP 443.

Not yet:
- incremental state: the first read after a write recomputes the state;
- signed snapshots, light-client proof APIs;
- key rotation at succession, and carrying subspaces other than the owner's;
- proof of work in the node's own writes;
- a frozen specification.

[Measurements](docs/bench/2026-11-11.md) show where the time goes.

**Agents playing a game through shared memory:** Claude Code (behind NAT) plays X,
Codex (cloud) plays O, Antigravity (cloud) referees. The fourth pane is the board as
the ledger sees it. [GIF](docs/media/agents-tictactoe.gif) ·
[MP4](docs/media/agents-tictactoe.mp4), 1 min 50 s.

## Documentation

| Document | What it is |
|---|---|
| [docs/vision.md](docs/vision.md) | The idea and its principles: the north star for every design |
| [docs/threat-model.md](docs/threat-model.md) | What is protected, from whom, and what isn't |
| [docs/operations.md](docs/operations.md) | Devices, agents, revocation, succession, relays, services |
| [docs/mcp.md](docs/mcp.md) | Shared memory for agents: tools, encryption, hidden names, registration |
| [docs/design/0003-ledger.md](docs/design/0003-ledger.md) | The ledger: trie, rules, resolution, replication |
| [docs/design/0004-authority-and-succession.md](docs/design/0004-authority-and-succession.md) | Authority, revocation, proof of work, succession (accepted; §12 lists what is built) |
| [docs/design/0001-architecture.md](docs/design/0001-architecture.md) | The original architecture; amended by 0003 (its §12 lists how) |
| [docs/bench/2026-11-11.md](docs/bench/2026-11-11.md) | Measurements: local benchmarks and the live mesh |
| [spec/](spec/) | The specification of format 1 (outline; the designs are normative meanwhile) |

## Layout

| Crate | What it is |
|---|---|
| [`sameroot-core`](crates/sameroot-core) | Formats, signatures, delegation, Logic 1, the ledger trie, resolution, succession plans: pure, no I/O |
| [`sameroot-store`](crates/sameroot-store) | Storage on redb: the ledger, persisted trie nodes, the derived state |
| [`sameroot-sync`](crates/sameroot-sync) | Replication protocol v5 over any stream; `examples/bench.rs` |
| [`samerootd`](crates/samerootd) | The node: iroh, relays, sessions, values, local RPC |
| [`sameroot`](crates/sameroot) | The command-line tool |
| [`sameroot-seal`](crates/sameroot-seal) | Application-level encryption: sealed values, hidden names |
| [`sameroot-mcp`](crates/sameroot-mcp) | Shared memory for agents: an MCP server over the local node |

| Directory | Contents |
|---|---|
| [`docs/`](docs/) | Vision, designs, operations, measurements, media |
| [`spec/`](spec/) | The specification of format 1 (outline) |
| [`vectors/`](vectors/) | Language-neutral conformance vectors; never regenerated to make a test pass |
| [`deploy/`](deploy/) | The relay deployment |
| [`scripts/`](scripts/) | Local multi-node scenarios |

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo run --release -p sameroot-sync --example bench   # local measurements
```

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.99.1). The minimum
supported Rust version is 1.91, the one iroh requires.

## Contributing and security

Issues are welcome; discuss before a pull request ([CONTRIBUTING.md](CONTRIBUTING.md)).
Report security problems privately ([SECURITY.md](SECURITY.md)).

## History and license

Sameroot is the Rust successor to the TypeScript
[DenkMitDB](https://github.com/denkmitdb/denkmitdb), under a new name.

MIT — see [LICENSE](LICENSE).
