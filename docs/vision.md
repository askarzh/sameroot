# Sameroot: vision

Status: accepted by the owner (2026-11-11). This page is the north star; the designs
in `docs/design/` must follow it, and a design that departs from it says so and why.

## The idea

**A shared ledger, like a blockchain, but without the chain.** That was the founding
idea. For readers who meet the project now: shared memory for your devices and AI
agents, kept like a ledger. Every node holds the same signed records, and one
fingerprint (a Merkle root) shows they match.

Sameroot began as peer-to-peer mail without mail servers: the mailbox is a general
ledger that every participant holds, and a message in it can be read only by the one
it is addressed to. Gateways to ordinary mail would come later. That needed a
foundation first.

The first attempt used OrbitDB on IPFS: peer to peer, content addressed, hashes all
the way down. It turned out slow and inflexible, and what didn't fit was how it keeps
a database consistent: a log in which every new entry links to the previous ones, so
consistency is the integrity of a chain, as in a blockchain.

Sameroot replaces the chain with a **Merkle tree**. The participants of a database
share a ledger; the ledger is committed to by a Merkle root; participants that hold
the same root hold the same ledger. Synchronising means comparing trees, not
replaying a history.

## Principles

1. **The ledger is the set of all accepted records**, like a general ledger. It only
   grows: nothing is physically deleted, rewritten or inserted into a history.
2. **Deletion is a record.** A negation names the records it negates. What a negation
   means, and who may issue one, is set by the consensus rules. The value bytes of a
   negated record may be dropped by the nodes; the signed record and its negation stay
   in the ledger.
3. **Consistency is a Merkle root over that set**, not a chain. The same records give
   the same root, whatever order they arrived in. There are no blocks, no links to
   previous entries and no global order.
4. **Consensus rules are a contract in the manifest.** When a database is created, its
   manifest fixes the contract that every participant and every node enforces:
   - **access**: who may write what;
   - **validity**: which records are valid on their own;
   - **resolution**: how the state is computed from the ledger, including negations
     and conflicts.
   The contract is deterministic: nodes holding the same ledger compute the same state.
   Changing the contract means a new database.
5. **State is derived from the ledger.** "The current value of a key" is the result of
   the contract's resolution over the ledger (last-writer-wins is one possible rule,
   not the database itself). Indexes and views are local and derived.
6. **Low trust, public access.** A database may be open to anyone. Nodes are not
   trusted; security comes from the contract and from separate mechanisms layered on
   top of it, not from who runs the node.
7. **Efficient structure.** Computation and the size of the tree must stay small. That
   is why Pollard was chosen originally. A light participant keeps only a root it
   trusts (one it computed, or one signed by someone it trusts) and checks records
   against it with short proofs. A proof shows that a record is in that snapshot.
   Since design 0004, the root also commits to an index of references, so a proof
   can show that no negation or revocation of a record is in that snapshot. It still
   can't show that no newer one exists elsewhere.
8. **An open platform; privacy is the application's.** Content is addressed by its
   hash and can be fetched by anyone from any node that has it, as in IPFS; the
   platform doesn't hide anything, because nodes aren't trusted to. Confidentiality
   belongs to applications: they encrypt values to the participants they are meant
   for, as a letter is to its addressee. Signed headers (who wrote, when, under which
   path) are public, so an application that needs private names encrypts or hashes
   them too.

## What follows

- **No finality.** Without a chain there is no agreed order: a record that arrives
  late can still change the derived state until every node has it. Every node then
  resolves it the same way. That suits shared knowledge, agent memory and
  coordination; it does not suit money or anything where a double spend matters.
- **Validity can't depend on derived state.** Whether a record is accepted must follow
  from the record, the manifest and its certificates alone; otherwise nodes that saw
  records in different orders would accept different sets and their roots would
  diverge. State-dependent logic belongs to resolution.
- **Rules that need an agreed order** (unique names, quotas, create-if-absent) cannot
  be decided by each node alone. If they are needed, they come as a separate, optional
  mechanism on top, not in the core.
- **A ledger grows forever.** Negated values can be dropped, but signed records and
  negations stay; "anyone may write" needs limits in the contract (and design 0004
  adds proof of work). To shed the history, the owner moves the database to a
  successor that carries the current state (design 0004 §8). The old database keeps
  only a stub that points to the successor. The rule holds within each database:
  nothing in it is ever rewritten.

## Not the goal

A chain of blocks, a global total order, BFT consensus, physical deletion or rewriting
of the ledger.

## Applications

Agents are the first application and the reason to revive the project now. The first
user is the owner: several agents (Claude, Codex, Gemini) on several machines (cloud
servers, a home computer, a work computer, a phone) should share one memory and work
together transparently, with no central server and no git repository in the middle.
Messaging between agents returns to the original idea of mail on a ledger. These
applications run on Sameroot; they don't define it.

## What this changes in the Rust work

- The tree commits to the **ledger** (all accepted records), not to the current
  winners per key. The design 0002 tree (a Merkle Search Tree over winners) doesn't
  follow principles 1 and 3 and will be replaced.
- Last-writer-wins becomes the default **resolution** rule of the contract.
- The access presets become canonical **contract programs**; a public preset is added.
- Carried over: signed records and their ids, certificates and voids (already
  negations), detached values, record verification, canonical CBOR, the store, the
  transport (iroh) and the sync skeleton.

## Open questions (for the next designs)

- The structure of the tree over the set of records: a Pollard-inspired structure
  keyed by record id, a hash trie, or another canonical set tree. Criteria: same set,
  same root; small updates; short proofs; cheap to compute and store.
- The contract language: the TypeScript version's Sameroot Logic 1 is the starting
  point.
- Expiry: how records with an expiry time relate to the root.
