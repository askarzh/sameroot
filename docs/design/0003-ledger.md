# Design 0003: the ledger

Status: **revision 2, accepted and implemented** (2026-11-11). Follows
[the vision](../vision.md). Replaces design 0002 (a Merkle Search Tree over the
current winners per key, never merged) and amends design 0001 as listed in §12. §13
says what the code does today. Format 1 is not frozen yet. Design 0004 amends it: the
root commits to a reference index too (0004 §4.1), and the protocol is version 5 (keep
lists travel with their voids, forwards replicate, a retired database answers with its
stub).

## 1. What changes and why

Design 0002 committed to the **state** (one winner per key). The vision commits to the
**ledger**: the set of all accepted records, from which the state is derived.

| | 0001/0002 | 0003 |
|---|---|---|
| Root over | current LWW winners | every admitted entry and void |
| Deletion | a key tombstone that replaces the old winner | a record; nothing leaves the ledger |
| Rules | hard-coded access presets | a contract in the manifest: access and validity programs, a resolution rule |
| State | is the tree | `state(ledger, manifest, asOf)`, a local index |
| Values | inline in sync, domain-separated hash | blobs by plain BLAKE3, fetched from any node |
| `readers` | part of the genesis | a local serving policy of each node |
| Tree upkeep | rebuilt on every change | updated along one path, nodes persisted, addressed by path |

Carried over: signed headers and their ids, certificates and delegation, voids,
canonical CBOR, Ed25519 checks, the store, the iroh transport, and the session
machinery hardened by the 0002 review (§7.5).

## 2. Records and admission

The **ledger** `L` of a database holds two kinds of records: **entries** (§3) and
**voids** (0001 §7.4). **Certificates** are not ledger records: they are dependencies,
stored by id and sent with the records whose chains use them.

Every record is admitted or not by a **pure function of the record, the manifest and
the certificates of its chain**. Nothing else is consulted: not other records, not
their order, not the state.

- **Entry:** strict Ed25519 signature; a complete, valid certificate chain with the
  entry's `op`, subspace, path and time inside every link's scope; `access(entry)`;
  `validity(entry)`; the limits of the manifest.
- **Void:** strict signature by the voided certificate's issuer or an ancestor in its
  chain (which makes that certificate a dependency of the void).

Two honest nodes that have seen the same records therefore admit the same records, in
any order. Two local, temporary states sit outside the ledger:

- **pending:** a certificate of the chain hasn't arrived yet;
- **deferred:** `ts` is ahead of the local clock by more than `tsSkew` (0001 §8.2). The
  node keeps the record and admits it locally when its clock catches up; that changes
  its root and restarts the exchange with its peers (§7.4).

**Clock limitation.** A node whose clock runs ahead admits future-dated records early,
and its root differs from its peers' until their clocks reach those timestamps. There
is no global clock to prevent that. Mitigation, local only: a node refuses to admit
deferred records while its clock is more than `tsSkew` ahead of the median time its
peers report in `hello`.

The ledger only grows. A record never leaves it: not on deletion, negation, expiry or
voiding. Those act through resolution (§5).

## 3. Entries

`Header = { v: 1, db, subspace, path, op, ts, exp?, valueSize?, valueHash?, target?, signer, cert? }`

`op` is one of:

- **Put:** a value under a path. `valueSize` and `valueHash` required; `exp` allowed.
- **Delete:** a key tombstone. No value, **no `exp`**: a deletion never expires and so
  never resurrects what it deleted.
- **Negate:** names one entry by id in `target` and asks resolution to ignore it. No
  path is required beyond the subspace's, no value, **no `exp`**. Only entries can be
  negated (not voids, not certificates); a negation can target another negation.

Negations can't form cycles: `target` is the id (a hash) of an entry that existed when
the negation was signed. Certificates gain the op `negate` in their area (0001 §7.2),
so negations can be delegated.

**Values** (amends 0001 §8.1): `valueHash = BLAKE3(value)`, the plain hash, so every
value is an iroh blob. Values are not in the tree and not in sync messages. A node may
keep or drop value bytes by its own policy; it must keep the records. Consequences,
accepted by the vision (principle 8):

- anyone can ask a node for a hash and learn whether it holds those bytes (a
  possession oracle); equal plaintexts have equal hashes across databases;
- every signed header (signer, path, time, size) is readable by anyone who can reach a
  node of the database;
- so applications encrypt values, and paths if they're sensitive, from the start. For
  the first application (shared agent memory) that is a requirement, not an option;
- an entry is admitted without its value. If nobody has the value, the state shows the
  key as "value unavailable"; resolution doesn't depend on value bytes;
- a fetch is capped at the signed `valueSize` and aborted beyond it.

## 4. The ledger tree

### 4.1 Requirements

1. The same set gives the same root, in any arrival order.
2. One new record changes few nodes.
3. Short inclusion and non-inclusion proofs; a light participant keeps only a root.
4. Prefix-aligned subtrees, so two replicas compare by subtree hash and skip what is
   equal.
5. No shape an attacker can distort beyond a small, bounded cost.

### 4.2 Choice

A **16-ary sparse trie keyed by record id**, hashed inside each node as a **binary
Merkle tree over its 16 slots** (the Jellyfish Merkle Tree arrangement). The 16-ary
shape gives depth ≈ log₁₆ n (≈ 5 at 10⁶ records) for sync and updates; the binary
hashing gives 4 sibling hashes per level in a proof (≈ 640 B at 10⁶ records). It needs
no ordering, levels or balancing rules: positions come from the record id.

Rejected: a binary trie (four times the depth for sync), the MST keyed by id (brings
back the rules and attacks of 0002), and Pollard (positions depend on insertion
order, which only a chain could fix).

### 4.3 Definition

Let `n(r)` be the 64 nibbles of record `r`'s id. For a nibble path `p` (0 to 63
nibbles), `R(p)` is the set of records whose id starts with `p`.

- A **node** exists at `p` if `p` is the root path (empty) or `|R(p)| ≥ 2`.
- Slot `i` (0–15) of the node at `p` is:
  - **empty** if `R(p‖i)` is empty;
  - a **record slot** if `|R(p‖i)| = 1`: it holds that record's kind and id;
  - a **child slot** if `|R(p‖i)| ≥ 2`: it refers to the node at `p‖i`.

So a node may have a single occupied slot (two ids sharing a longer prefix). The shape
is a function of the set alone.

**Hashes** (separate contexts for each kind of preimage):

```
slotHash(empty)        = 32 zero bytes
slotHash(record k, id) = BLAKE3_derive("sameroot 1 ledger leaf",   k ‖ id)          // 1 + 32 bytes
slotHash(child p‖i)    = nodeHash(p‖i)
pair(a, b)             = BLAKE3_derive("sameroot 1 ledger pair",   a ‖ b)           // 64 bytes
nodeHash(p)            = BLAKE3_derive("sameroot 1 ledger node",   depth(p) ‖ root) // 1 + 32 bytes
```

`binaryRoot` folds the 16 slot hashes pairwise into 8, 4, 2, 1. `pair(0, 0) = 0`, so
an empty half of a node costs nothing. The **ledger root** is `nodeHash(empty path)`;
the empty ledger has the root of a node with 16 empty slots. `k` is 0 for an entry, 1
for a void.

**Wire form of a node** (canonical CBOR):

```
{ "v": 1, "d": depth, "o": u16, "r": u16, "s": [ … ] }
```

`o` has a bit set for every occupied slot and `r` for every record slot (`r ⊆ o`). `s`
holds, for each occupied slot in slot order, either `[k, id]` (record slot) or the
child's node hash (child slot).

**Receiver checks** for a node requested at path `p`: canonical decoding with exactly
these fields; `d = |p|`; `r ⊆ o`; `popcount(o) = len(s)`; each record id starts with
`p‖i` for its slot `i`; `k` is 0 or 1; the root node may have any number of occupied
slots, and every other node at least one; recomputed `nodeHash` is the hash the node
is presented as. Records later served for a record slot must have that id and kind.

### 4.4 Proofs

- **Inclusion:** for each level from the root, the 4 sibling hashes of the path's slot
  inside the node and the depth; at the end the record's kind and id. The verifier
  recomputes up to the root.
- **Non-inclusion:** the same down to an empty slot, or to a record slot whose id
  shares the prefix and differs from the queried id.
- A proof is relative to a root. A light participant trusts a root because it computed
  it or because someone it trusts signed it (§8). A proof can't show that a negation
  is being withheld: "this entry is in the ledger" is not "its value is the current
  state".

### 4.5 Grinding

Record ids hash the unsigned header, so an attacker controls them cheaply: a shared
`k`-nibble prefix with a chosen record costs about `16ᵏ` header hashes, and with any of
its own records about `16^(k/2)`. Depths of 10 to 14 nibbles on one path are within
reach. The damage is a few extra single-slot nodes on that path, bounded by depth 64;
other paths are unaffected.

## 5. The contract

### 5.1 Manifest (amends the 0001 genesis)

```
Genesis = Signed<{
  v: 1, nonce, createdAt, name, owner, predecessor?, meta?,
  contract: {
    access:     Program,                  // Sameroot Logic 1 → bool
    validity:   Program,                  // Sameroot Logic 1 → bool
    resolution: { rule: Text, params: Map },
  },
  limits: { maxValue, maxPath, tsSkew, maxTtl? },
}>
```

`readers` is removed: the platform is open, so "who may read" would only be a request
to nodes. Each node has a local serving policy instead (rate limits, what it stores
and fetches). Changing the contract means a new database.

### 5.2 Sameroot Logic 1

A program is `{ "<op>": [args] }`, the TypeScript version's language with semantics
fixed for every implementation:

**Values:** `bool`, `uint` (0 … 2⁶⁴−1), `bytes`, `list`. Text literals are UTF-8
`bytes`. No floats, no null, no arithmetic (so no overflow).

**Operators:**

| Op | Arguments → result |
|---|---|
| `var` | `name` → the input; `[name, default]` → the input or the default if absent (same type required) |
| `==`, `!=` | two values of one type → bool (lists compare element-wise) |
| `<`, `<=`, `>`, `>=` | two `uint` or two `bytes` (byte-wise lexicographic) → bool |
| `and`, `or` | ≥ 1 bool → bool, left to right, short-circuit |
| `!` | bool → bool |
| `if` | `cond, then, else` (or chained `c1, t1, c2, t2, …, else`) → the chosen branch |
| `in` | value, list → bool (element equality) |
| `cat` | ≥ 1 bytes → bytes |
| `startsWith` | bytes, bytes → bool; or list, list → bool (component-wise prefix) |
| `at` | list, uint → the element (out of range is an error) |
| `len` | list or bytes → uint |
| `hex` | bytes → lowercase hex as bytes |

**Errors deny:** an unknown operator, a missing input without a default, a type
mismatch or an out-of-range index makes the program return false. Branches that short
circuit or `if` doesn't take are not evaluated and can't error.

**Bounds:** program ≤ 16 KiB of canonical CBOR, nesting ≤ 16 (the CBOR profile's
limit), ≤ 10,000 evaluated operators.

**Inputs** (the record and its chain only):

| Input | Type | Notes |
|---|---|---|
| `kind` | bytes | `entry` (voids aren't run through programs) |
| `op` | bytes | `put`, `delete`, `negate` |
| `path` | list of bytes | components |
| `shared` | bool | the shared subspace |
| `subspaceOwner` | bytes (32) | absent if shared |
| `signer` | bytes (32) | |
| `chainRoot` | bytes (32) | the key the certificate chain ends in (= `signer` without a chain) |
| `owner` | bytes (32) | the database owner |
| `ts` | uint | |
| `exp` | uint | absent if none |
| `valueSize` | uint | puts only |
| `valueHash` | bytes (32) | puts only |
| `target` | bytes (32) | negations only |

**Presets** are canonical programs (exact CBOR in the test vectors):

- `own-subspace`: `!shared and subspaceOwner == chainRoot`. **Open write:** any key
  may write its own subspace; the ledger of such a database is open to anyone.
- `owner-only`: `chainRoot == owner`.
- `allowlist`: `chainRoot in [keys…]`.
- `shared-allowlist`: `shared and chainRoot in [keys…]`.
- `public-shared`: `shared` (anyone writes the shared subspace).
- `put-only`: any of the above `and op == "put"`.
- `namespace-per-writer`: `shared and at(path, 0) == "agents" and at(path, 1) == hex(chainRoot)`.

`validity` defaults to `true`; the limits of the manifest are checked by the
implementation before the programs run.

### 5.3 Resolution

The state is `state(L, manifest, asOf)`: a function of the ledger, the contract and an
explicit evaluation time. Two nodes with the same root and the same `asOf` compute the
same state. Every rule runs the same pipeline:

1. **Voided:** an entry whose certificate chain contains a voided certificate has no
   effect. Voids are irreversible.
2. **Negated:** an entry `e` is negated if some *effective* negation `N` targets it and
   `N`'s signer may negate `e`. A negation is effective if it is neither voided nor
   negated itself. This is well-founded (targets precede negations) and is computed
   iteratively in dependency order, so long chains are fine. With negations N1 and N2
   of P and N3 of N1, P stays negated by N2: restoring needs every negation of P
   negated.
3. **Expired:** a put with `exp ≤ asOf` has no effect.
4. **Rule,** per key, over the remaining entries:
   - **`lww`** (default): the put or delete with the largest `(ts, id)`; a delete
     means no value.
   - **`earliest`:** the put or delete with the smallest `(ts, id)`. Timestamps are
     claimed by writers, so this is "smallest claimed time", not "first writer"; a
     backdated late entry can still win. Use it only where writers are trusted.
   - **`collection`:** the set of remaining puts (append-only collections, inboxes).

**Negation right** (resolution parameter `negate`): `author` (default: `N`'s chain
root equals `e`'s chain root), `owner` (the database owner), or `both`. `both` suits
moderated public databases.

Limits that count records (quotas) are not part of format 1: they would need agreement
on order, or bound only the state. Nodes keep local budgets (0001 §9.3) instead.

## 6. State

The state is a **local index**: path → current value per resolution at `asOf` = the
node's clock, updated as records arrive. It is not part of consensus and has no root in
format 1. Reads may pass an explicit `asOf` (needed for "as of" reads and for tests). A
state root for "the current value of k is v" proofs can come later.

## 7. Replication protocol v4

Version 4 is version 3 without values in the session, beyond the small ones that ride
inline (item 6). Nodes of the two versions don't talk: `hello` carries the version.

### 7.1 Messages

1. `hello`: protocol 4, nonce, database, needGenesis, the sender's clock.
2. `root {hash, count}` both ways; again when the root changes, **at most once per
   second** (coalesced).
3. `getNodes {paths}` (≤ 64 nibble paths) → `nodes [bytes]`: the peer's **current**
   node at each path, or nothing if it has no node there. Frames ≤ 8 MiB, the last
   with `done`.
4. The puller compares each received node with its own node at the same path, slot by
   slot. Equal slot hashes are skipped. A peer record slot it lacks goes into `want`.
   A peer child slot where it has an empty or record slot, or a different child,
   is walked further.
5. `want {ids}` → `records [bytes]`, each with the certificates of its chain. Frames
   as for `nodes`. A put's value up to 64 KiB may ride along (`v`); the receiver keeps
   it only if it matches the signed `valueHash` and `valueSize`.
6. Values travel over **iroh-blobs** by `valueHash`, on the same endpoint as the
   ledger. A node serves any value it holds to anyone who asks by hash (§3). A put
   admitted without its value is fetched at once from the peers of the database's
   sessions (they hold the record, so most likely the value), verified while it
   streams (BLAKE3 verified streaming), and resumed after a break; every 10 s the node
   fetches again whatever its ledgers reference and it lacks. A node writes its own
   value, committed, before the record. Discovery of other providers is not part of
   format 1. Version 3 carried values in the session (`getValues {hashes}` →
   `values`); version 4 drops that: a transport change, not a format change.

### 7.2 Why there are no stale walks

Nodes are addressed by path, and the set only grows, so a node that exists at a path
keeps existing. A peer answers from its current tree; if its tree moved on, the puller
just sees newer content at the same path and fetches more. A pull is a union: nothing
is reconciled or rolled back.

### 7.3 Cost

A new record costs the peer about `depth` nodes and one record. Replicas that differ
in `k` records exchange at most about `k · depth` nodes, fewer when the differences
share prefixes.

### 7.4 Pull control

- One pull per (own root, peer root) pair; a new root on either side, including a
  locally admitted deferred record, allows a new one.
- A pull that runs out of its node budget (0002 §4) ends **incomplete**; the next pull
  starts from the root again and skips the subtrees already equal.
- Fake trees cost the puller at most the node budget per pull before records fail to
  arrive or verify; a peer whose `want` answers repeatedly omit records it advertised
  is deprioritized locally.

### 7.5 Carried over from the 0002 review

Dedicated reader task, frame splitting with `done`, the outbox cap, the liveness flag,
the per-pull node budget, capped id sets, certificates stored only with an admitted
record, retryable transient failures, the store's generation counter. Node limit:
≤ 16 slots, so ≤ 1 KiB.

## 8. Signed snapshots (next)

`Snapshot = Signed<{ v: 1, db, root, ts }>`: "I had this ledger at time ts", unchained.
It is how a light participant trusts a root, and the basis for "as of" reads.
Snapshots are not ledger records. Two snapshots of one signer at one `ts` with
different roots are evidence of a fault, not proof of a fork: without finality, honest
nodes can briefly hold different roots.

## 9. Store

- Entries and voids by id; certificates by id. Values by `valueHash` in an
  iroh-blobs store next to the ledger store (`blobs/`), not in it.
- **Ledger nodes are persisted by path** and updated along one path per admitted
  record.
- The state index is a derived table, rebuildable from the records.
- Schema 4: schema 3 without its values table. A schema 3 store opens as schema 4;
  the node moves its values into the blob store at start, then drops the table.
  **No migration from formats before 0003:** the genesis and `valueHash` change, so
  those databases are recreated. They are test data.

## 10. Demonstrator (weeks 2–4)

Tests that show the vision works, in CI:

1. **Order independence:** the same records fed to N replicas in random orders, with
   partitions and rejoins, give the same ledger root and, at one `asOf`, the same
   state, for each resolution rule. Property tests over many seeds.
2. **Negations and voids:** a put negated by its author disappears from the state on
   every replica; a negation by a key without the right has no effect; N1, N2, N3 as
   in §5.3; a voided certificate removes its entries' effect; a chain of 10⁵
   negations resolves.
3. **Proofs:** inclusion and non-inclusion proofs verify against a root and fail
   against another; a proof through a single-slot node; tampered siblings fail.
4. **The honest limit:** a node that withholds a negation serves a valid inclusion
   proof for a negated entry. The test documents it.
5. **Contracts:** every preset as a program decides like today's hard-coded checks;
   Logic 1 vectors, including every error-denies case and short-circuiting.
6. **Tree canonicality:** ids sharing long prefixes; the same set built in different
   orders gives the same nodes at every path.

## 11. Open questions for the owner

Resolved from the review, unless the owner decides otherwise:

1. Tree shape: the 16-ary trie with binary hashing inside nodes (§4.2).
2. Default negation right: `author`; `owner` and `both` are explicit choices.
3. `public-shared` doesn't require `maxTtl` in consensus (a preset is just a program,
   and `maxTtl` bounds the state, not the ledger); tools default to setting one.

## 12. Amendments to 0001

| 0001 | Change |
|---|---|
| §5 genesis | `access` preset → `contract` (programs, resolution); `readers` removed |
| §7.2 certificate area | adds the op `negate` |
| §8.1 value hash | plain BLAKE3, values are iroh blobs |
| §8.2 `deletePrefix` | not in format 1 (no prefix negation yet) |
| §9.2 rule inputs | replaced by the Logic 1 inputs (§5.2) |
| §9.3 local budgets, "incomplete" | kept; quotas stay local |
| §10.1 retention | records are never dropped from the ledger; values may be dropped after expiry, negation or voiding |
| §12 sync | replaced by protocol v3 (§7) |
| §13 replication admission, blob gate | removed: serving is open; nodes apply local serving policy |
| Presets `shared-allowlist`, `put-only` | kept as programs (§5.2) |

## 13. Implementation status (2026-11-12)

Implemented, as designed: records and admission (§2–§3), the ledger trie with
receiver checks and proofs (§4), the contract with Sameroot Logic 1 and the presets
(§5), resolution with voids, negations, expiry and the three rules (§5.3), the state
as a local cached index (§6), protocol v4 with path-addressed nodes (§7), the store
(§9, schema 4), and the demonstrator tests of §10.

Additions in the implementation:

- **Push** (§7.1): a node sends fresh records (its own writes, and records it just
  admitted from a peer) to its sessions at once, as an unrequested `records` frame;
  the trie walk remains the way to catch up. The `root` window is 100 ms.
- **Values through iroh-blobs** (§7.1.6, since 2026-11-12): `records` frames carry
  the value of a put up to 64 KiB. Every other value is fetched by `valueHash` from the
  database's peers over iroh-blobs, verified while it streams and resumed after a
  break, with a sweep every 10 s for what is still missing. A node commits its own
  value before the record. Protocol v3's `getValues` is gone (v4), and store schema 3
  values move into the blob store on start.
- **Application-level encryption** (vision principle 8, §3): `sameroot-seal` seals
  values (XChaCha20-Poly1305, bound to database and path) and hides key names
  (per-component keyed tokens); the shared memory application uses both. The
  platform is unchanged.

Not yet: signed snapshots (§8), a state root, incremental state and batched ingest
(see [the measurements](../bench/2026-11-11.md)), the specification in
[`spec/`](../../spec/). Design [0004](0004-authority-and-succession.md) (accepted)
amends §4.3 (the composite root with a reference index) and §5.3 (voids with keep
sets); it is not built yet.

