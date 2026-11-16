# Design 0004: authority, revocation, spam cost and succession

Status: **revision 3, accepted by the owner** (2026-11-12). Follows [the vision](../vision.md), builds on
[design 0003](0003-ledger.md) and amends its §4.3 (the root, §4.1 here) and §5.3 (voids,
§5.3 here). The design was argued with Codex, Gemini and Fable in five rounds; §10 lists
what was rejected and why. Format 1 is not frozen: every format change here lands before
it freezes.

## 1. Goals

The same mechanism must serve two modes, and every combination of them:

- **public:** any key writes within its own authority (its own subspace, or an open
  shared area), with no certificate and no setup;
- **secure:** only writers the owner certified write.

The ledger may be stored and served by **untrusted nodes**. Adding a record must still
follow one deterministic rule that every node computes for itself (0003 §2): admission
is a pure function `f(record, manifest, chain)`; there is no vote, order or finality.

Two properties guide every choice: **openness** (a stranger can join, store, serve and,
where the contract allows, write) and **reliability** (no honest node is ever led to a
different state by arrival order, withholding or a stolen key it has heard about).

## 2. Three independent axes

| Axis | Set by | Public | Secure |
|---|---|---|---|
| Who writes | the contract, checked by every node | `own-subspace`, `public-shared` | `owner-only`, `allowlist` |
| Who stores and serves | nobody: serving is open, each node has a local policy | anyone | anyone, untrusted included |
| Who reads | application encryption (`sameroot-seal`) | everyone | holders of the memory key |

Consensus governs only the first axis. An untrusted storer runs the same `f`. It can
store, serve, relay, delay and withhold. It cannot forge (signatures), alter (hashes and
the root), push an invalid record past an honest node (every node checks), or read sealed
values. In the secure mode it still sees metadata: signer keys, `ts`, sizes, record
counts and hidden-name tokens.

The mode is part of the immutable contract; changing it means succession (§8).

## 3. Authorization: certificates, not pre-made or derived keys

Delegation certificates (0001 §7, unchanged in shape) are the only authorization
mechanism. Authority derives from the owner key **by signature**: the subject generates
its own key, and its secret never leaves the machine. Rejected alternatives are in §10.

Rules and conventions:

- **The chain:** owner → device → agent, at most 3 links. The node holds **one key per
  agent** (Claude, Codex, Antigravity …), each certified by the device key with a narrow
  `pathPrefix` and a short window. A misbehaving agent is then cut off without touching
  the device.
- **Separate keys:** device and agent signing keys stay separate from the iroh endpoint
  key. They have different exposure and lifetimes, and merging them would tie authorship
  to network identity. An optional `endpoint?` field in a device certificate binds the two
  where wanted; it is added before the freeze (§9.4).
- **Owner key:** kept offline. A 2-of-3 FROST owner key (ordinary Ed25519 signatures,
  no format change) is deferred.
- **Public writers:**
  - a **bare key** writes its own subspace with zero setup. It is disposable: if it
    leaks, it can only kill itself (§5.3);
  - the reference client instead creates a **cold root** K by default. K owns the
    subspace and certifies a hot key H (`K → H`). This works today, because
    `own-subspace` compares `subspaceOwner` with `chainRoot`, not with the signer. After
    a leak, K voids the old cert with a keep set (§5) and certifies a new hot key, and
    the subspace stays the same. This is KERI-style recovery with no new field.

### 3.1 The hole this design closes

`Cert::covers` checks the window `[notBefore, notAfter)` against the entry's `ts`, and
the signer sets `ts`. A stolen key backdates into the window, so expiry does not stop a
thief, and today the only remedy is a total void that also erases honest history.
Without a trusted clock no rule can tell a backdated entry from an honest one by its
contents. A key that is not compromised has to say which entries stay (§5).

## 4. Where keys live

There is no registry of writer keys:

- the owner key is in the genesis, which every node holds;
- the signer's key is in each entry header;
- the certificate chain travels with each record (`records` frame, field `c`) and is
  stored in each node's `CERTS` table.

A record proves its own authority, so every node decides alike. Voids are ledger records
and enter the root; certificates are not (decided, §9).

**Every record carries its chain, voids included.** A void carries the chain up to and
including the certificate it voids, so a certificate can be voided before its first use. A
node retains every certificate that a retained entry or void references. Chains are
verified in full on arrival, for voids as for entries:
- each signature;
- `db`;
- `parent.subject == child.issuer`;
- the root.

Today `verify_void` walks the issuer fields without checking signatures. Ids bind content
and entries check signatures in `authority()`, so this is not exploitable now, but it is
fixed with this design.

### 4.1 The ledger commitment: records and references (amends 0003 §4.3)

A client that receives an entry and its inclusion proof cannot tell whether a void of its
certificate, or a negation of the entry, exists elsewhere. The root therefore commits to
a second, derived structure: which records reference which subjects.

```
refKey(tag, s) = BLAKE3_derive("sameroot 1 ref subject", tag ‖ s)
                 ; tag 0: a certificate id, 1: a public key, 2: a target entry id

indexed:  a cert void     → refKey(0, void.cert)
          a key void      → refKey(1, void.key)
          a negation      → refKey(2, header.target)
          (puts, deletes and forwards reference nothing)

bucket(k)      = { idsRoot, count }   ; idsRoot: a ledger trie (0003 §4.3) over the
                                      ; referencing records, (kind, id) leaves
refLeaf(k, b)  = BLAKE3_derive("sameroot 1 ref leaf", k ‖ b.idsRoot ‖ u64(b.count))
refRoot        = a 16-ary sparse trie over the refKeys, with refLeaf slots
                 (otherwise the node and pair hashing of 0003 §4.3)
recordRoot     = the 0003 ledger root over every admitted record
ledgerRoot     = BLAKE3_derive("sameroot 1 ledger commitment", recordRoot ‖ refRoot)
```

**Rules:**
- Every admitted record that references a subject is indexed, effective or not.
  Effectiveness belongs to resolution, so the index is a pure function of the set.
- **Equal `recordRoot`s imply equal `refRoot`s.** Sync compares and walks only the record
  trie. A node derives its own index and never accepts index nodes from a peer.
- **Which root means what:**
  - `recordRoot` is used by `keep.root`, `carryRoot`, `root` messages and `getNodes`;
  - `ledgerRoot` is used by `cutRoot`, signed snapshots and light proofs.

  APIs name the two explicitly.
- **Cost:** a put or delete changes only the record trie. A void or negation also updates
  one bucket and one path of the reference trie.
- **Light proof that nothing revokes or negates entry e:**
  - e's inclusion under `recordRoot`;
  - a non-inclusion proof under `refRoot` for each certificate in e's chain (or for its
    signer key, if e has no certificate), and for e itself as a target;
  - both roots, hashing to the trusted `ledgerRoot`.

  If a bucket exists, its full id list and records are fetched instead, and `count`
  prevents a subset from passing as the whole.
- **Limit:** absence is proven relative to the `ledgerRoot` the client trusts, typically
  from a signed snapshot. Two bound hashes don't prove that the index was derived
  faithfully: that rests on the root's signer, and any full node can catch a wrong one.

## 5. Revocation: Void with a keep set

### 5.1 Record (replaces the 0001 §7.4 void)

```
Void = Signed<{
  v: 1, db,
  cert?: digest,              ; exactly one of cert | key
  key?: pubkey,               ; a bare key: covers its own certless entries
  keep?: { root: digest, count: uint },
  before?: uint,              ; ms; requires keep
  work?: uint,                ; PoW nonce, as for entries (§6)
  signer
}>
```

`keep.root` is a ledger-trie root (0003 §4.3) over the kept entry ids, with every leaf of
kind 0. It reuses the trie code, the proof format and the sync diff. `count` is the number
of kept ids. With no `keep` the void is **total**, as today.

### 5.2 Admission (pure)

- **Cert form:** `signer` is the certificate's issuer or an issuer above it
  (`verify_void` today). The subject never voids its own certificate: a thief holds the
  same key and would void with an empty keep.
- **Key form:** `signer == key`, with no `keep` and no `before`. This is a self-kill
  switch, harmless in a thief's hands, because a thief with the key can already
  overwrite everything.
- `before` without `keep` is rejected.
- **The keep set is a mandatory dependency.** The void travels with its full list of kept
  ids. Admission verifies that the ids are distinct and canonically ordered, and that they
  match `root` and `count`. `count ≤ maxKeepCount`, an immutable contract limit. A void
  whose list is missing stays pending, like a record with a missing certificate. A void
  can therefore never leave covered entries unresolved for lack of its own list.
  (Two experts of three; the third found the dependency heavy and preferred only the
  limit.)
- **Work:** voids meet the contract's work floor unless their chain root is the owner or
  another root the contract trusts. A self-issued chain (a cold root of its own) is not
  exempt.

### 5.3 Resolution (replaces 0003 §5.3 step 1)

A void V **covers** entry e when both hold:

- V.cert is in e's chain, or e has no certificate and V.key = e.signer;
- `before` is absent, or e.ts < V.before.

Then:

1. If any covering void has no `keep`, e has no effect.
2. Otherwise e has effect only if it is a member of `keep.root` of **every** covering
   void. Restrictions intersect.
3. Membership is known by holding the full keep set (the node recomputes `root` and
   checks `count`) or an inclusion proof. If it is unknown, e is **unresolved**: it has
   no effect, and the API reports it as unresolved rather than absent. A storer that
   withholds a proof must not be able to revive a revoked entry.
4. Negations signed under a covered certificate follow the same rule: they are entries.
5. **Voids under a voided certificate:** a void with `before` covers entries only. A void
   without `before` also disables every void whose authority depends on the certificate
   it targets. A keep set cannot preserve a subordinate void. Ancestors are evaluated
   first; strict ancestry keeps the graph acyclic. Routine rotation (`before = notAfter`)
   therefore leaves a device's honest revocations intact, and a total void of a thief's
   device certificate also undoes that thief's sabotage voids.
6. Voids are irreversible as records. Effects do **not** only shrink: voiding a negation
   restores its target, and a superior void can disable a subordinate one. The invariant
   is that resolution is a deterministic function of the admitted set (and `asOf`),
   stratified by chain depth, so every arrival order converges.
7. A keep set that turns out too narrow is fixed by a new certificate and re-signed
   puts, never by loosening.

### 5.4 Availability of keep sets

A node holding the thief's entries holds a superset; it cannot derive the kept subset, so
a keep set is real data. Rules:

- The keep list travels with the void (§5.2), so every node that admitted the void holds
  it. A node **must retain and serve** it for as long as it keeps the void. Unlike
  values, it may not drop the list by policy.
- `records` frames may carry a keep proof for a covered entry, for light readers.
- The tool exports the keep set as a manifest, for backups.
- If the issuer vanishes, nothing is lost: the list lives wherever the void lives.

### 5.5 `before` and expiry

A void with `before = notAfter` and a keep set covers every valid entry under that
certificate. Once it is known, anything the thief backdates later has no effect. This
closes the expiry hole **by explicit sealing**, not by expiry alone. A grace period
before sealing is operator policy, not proof of creation time.

Use it **once per certificate, at expiry**. Periodic seals of live certificates stack:
an old entry would need one proof per seal. They wait for proof aggregation (§11). A void
with `before` leaves the certificate alive for later timestamps; a thief holding a live
certificate simply writes in the present, and only a total or keep-limited void without
`before` stops that.

### 5.6 Tooling

- Each node keeps a local `first_seen` time per record. It is not part of the format: it
  is the only clock in the system a thief cannot set.
- `sameroot void <cert> --keep-before <local time>` builds the keep set from that index,
  prints the entries it would drop, and signs only after confirmation.
- Rotation becomes routine: issue a new certificate, then void the old one with
  `keep = everything seen under it` and `before = notAfter`.

## 6. Spam cost: proof of work

### 6.1 Format

- `Header += work?: uint`: a nonce, omitted when 0. It is part of the signed header, so
  it is part of the entry id. Voids carry the same field (§5.1).
- Logic 1 gains an input `work`: the number of leading zero bits of the entry id.
- Mining varies `work` until the id has enough zero bits, then signs once.

### 6.2 Contract

Difficulty is a program, so a contract can price exactly what it wants:

```
validity = if(chainRoot == owner, true,                 // certified writers are exempt
             if(valueSize < 4096, work >= 20, work >= 24))
```

### 6.3 Cost

BLAKE3 over a 300-byte header, measured on one ARM server core: 2.0 M hashes/s.

| Leading zero bits | Mean time per record (1 core) |
|---|---|
| 16 | 0.03 s |
| 20 | 0.66 s |
| 22 | 2.3 s |
| 24 | 7 s |

### 6.4 What it does and does not do

PoW is **pure** and **order independent**: the check reads only the record. It prices
spam, but it does not stop it:

- a GPU computes BLAKE3 about a thousand times faster than a laptop;
- `ts` is chosen by the signer, so work can be stockpiled and released later;
- records never leave a ledger, so spam that got in stays until succession (§8).

Memory-hard functions (Argon2) would even out the hardware, but every node would pay the
same cost to verify every record during sync; rejected. PoW is one layer among several:
`maxValue`, a mandatory TTL in public areas, owner moderation (negation right `owner` or
`both`), local serving budgets, and GC by succession. Format 1 ships the field and the
input; contracts start with difficulty 0 until spam is a real problem.

### 6.5 Other costs, later: stamps

The owner wants contracts to admit other costs, for instance payment in ETH or another
currency. Admission must stay pure, so it cannot consult an external chain: the state of
another blockchain is neither local nor final, and two nodes could disagree about it. The
deterministic shape is a **stamp**:

- an issuer named in the contract (a payment service, possibly a smart contract's
  operator) takes the payment and signs a stamp `{db, subject, quota, window}`;
- the stamp travels with the subject's records, like a certificate.

A quota cannot be enforced at admission: that would need order. Resolution can enforce it
deterministically, by counting only the `quota` entries with the smallest ids under each
stamp. This bounds the state, not the ledger. PoW still prices storage. Stamps are a
later design; nothing in format 1 blocks them.

## 7. Moderation in the public mode

- **Owner negation:** with negation right `owner` or `both` (0003 §5.3), the owner
  cancels any entry. It exists today.
- **Key kill switch:** the key-form void (§5.2).
- **Banning another person's bare key** is not in format 1. It would let the owner erase
  self-sovereign writers wholesale; a contract that wants it uses negation per entry, or
  moves to a successor that excludes the key.

## 8. Succession and garbage collection (approved)

A ledger never forgets within itself. GC, a new contract, a new owner key and a new
memory key all happen by **succession**: a new database whose genesis inherits the state
of the old one at a cut. Pruning inside one database is unsafe: negating a negation can
revive a value thought dead.

### 8.1 Records

```
Genesis += predecessor?: { db, cutRoot, cutCount, asOf, carryRoot? }
Genesis += nextOwner?: digest          ; H(next owner public key), KERI-style
Forward  = Signed<{ v: 1, db, successor, owner, cutRoot }>   ; ledger record, leaf kind 2,
                                                              ; signed by the parent's owner
```

The link goes both ways. The child's `predecessor` names the parent and the cut. The
parent's `Forward`, signed by the old owner, is what makes the child legitimate, because
anyone can write a genesis that claims a parent.

`Forward` is the third leaf kind of the trie (0 entry, 1 void, 2 forward). It names the
child's `owner`, so admission stays pure: if the parent's genesis has `nextOwner`, a
`Forward` is admitted only when `H(owner) == nextOwner`. A thief holding the parent's
owner key then cannot appoint itself. To follow, a node additionally checks that the
child genesis matches the forward: owner, successor id, parent and cut. Without
`nextOwner`, conflicting forwards are a visible fork: nodes pin the first successor they
follow and tell the user.

### 8.2 What is carried

- **Rewrite (format 1):** the owner computes `state(parent at cutRoot, asOf)` and signs
  the winners anew in the child. This is required whenever the memory key rotates, since
  ciphertexts, value hashes and hidden names all change. Authorship is flattened, and the
  parent's entries become provenance.
- **Verbatim (later):** the original signed entries are admitted in the child by
  membership in `carryRoot`, and nodes holding the parent recompute and compare. This is
  needed once several authors' signatures must survive.
- The child's contract governs only the child's own records.
- Floor rule: every entry of the child has `ts ≥ genesis.createdAt`. It is pure, and it
  stops backdating below the carried state.

### 8.3 Transition

1. **Cut:** the owner syncs with reachable peers and picks its own root as `cutRoot`.
2. **Publish** the child's genesis and the parent's `Forward`; issue certificates in the
   child. Certificates bind `db`, so a device that gets none is revoked completely and
   for free.
3. **Read-only grace period** (days to weeks):
   - a node that sees `Forward` stops writing to the parent;
   - records still arriving in the parent are late. They go to a visible inbox, and a
     device re-submits its **own** late writes to the child as fresh entries, never by
     silent replay.
4. **GC:** the parent's records, trie nodes, certificates and unreferenced blobs are
   deleted. A stub stays forever: the genesis, the `Forward` and `cutRoot`, about 1 KB.
   A device offline longer than the grace period still finds the successor.

### 8.4 Limits

Old ciphertexts were served by hash to anyone. Rotating the memory key protects only
future data. GC is local: it cannot retract copies held elsewhere.

## 9. Questions settled by the expert meeting and the owner

Settled in a second meeting with Codex, Fable and Gemini 4 Carbon (2026-11-12, two
rounds). Q1 and Q3 were unanimous.

1. **Certificates stay dependencies, not ledger records.**
   - Ledger membership can never be an admission condition.
   - Void-before-use works because voids carry their chain (§4).
   - Used certificates are already committed through `Header.cert`.
   - Publishing every grant would expose the device and agent inventory (`Cert.name`,
     subjects) permanently, and would invite certificate spam in the public mode.
   - A member registry, where wanted, is an application convention: the owner writes
     `put /.grants/<certId>` with the signed certificate as the value, sealed in the
     secure mode.
   - There is no `certsInLedger` flag and no `Grant` record.
2. **Hidden recovery keys: not needed.**
   - K is visible, but the certificate K → H exposes it anyway, and knowing a public key
     doesn't help an attacker.
   - Linking across databases is the real risk. The reference client derives an
     independent cold root per database from a seed (hardened derivation, outside
     consensus).
   - `revHash` and `subspace = H(pubkey)` are rejected: both break `Subspace::Owner` and
     `subspaceOwner == chainRoot`.
3. **Light-client completeness: a general reference index in the root** (owner's
   decision, option B; the alternatives were a void-only index and deferring to
   snapshots). It is specified in §4.1. It makes the absence of a void or a negation
   provable under any root a client trusts. A superseding put remains unprovable under a
   bare root: the state depends on time, so a state index belongs in signed snapshots
   (0003 §8).
4. **Strict parsers stay strict** (owner's decision). Decoders keep rejecting unknown
   fields. A field known to be needed is added as optional before the freeze: `endpoint?`
   in a device certificate (§3). Any other future field needs `v: 2`.

## 10. Considered and rejected

| Proposal | Why not |
|---|---|
| A list of 100 pre-made keys in the genesis | The owner creates and ships secrets; the set is frozen; no scope, expiry or single revocation |
| A Merkle commitment of keys | The same, only smaller |
| BIP32-Ed25519 public derivation | A leaked child secret plus the xpub yields the parent secret; children are expanded scalars, not iroh seeds |
| SLIP-10 hardened derivation | Nodes cannot verify without the seed; kept only as a backup convenience outside consensus |
| `prev` chains + `keep` heads | One withheld ancestor hides whole histories; backups and shared keys fork; O(N) proofs; publishes write order; reverses "the ledger is a set" |
| Cross-signer `anchors` | Adds a social graph to the metadata; no trusted time |
| Short certificate lifetimes as the fix | `ts` is the thief's; a window bounds only honest writers |
| Owner anchors that reject entries missing from a later anchor | Admission would depend on other records and on order |
| Memory-hard PoW | Verification costs every node the same as solving |
| Per-key quotas at admission | Need order; possible only in resolution or as local policy |

## 11. Build order

1. **Format, before freezing:**
   - `Void` v1 with `cert | key`, `keep`, `before` and `work`, the keep list as a
     dependency, and `maxKeepCount`;
   - the `work` field and the Logic 1 `work` input;
   - `predecessor` and `nextOwner` in the genesis;
   - the `Forward` record (`owner` included) as leaf kind 2;
   - the reference index and the composite `ledgerRoot` (§4.1), with `recordRoot` and
     `ledgerRoot` named apart in every API;
   - `endpoint?` in device certificates; parsers stay strict (§9.4).
2. **Resolution and store:**
   - full chain verification for voids, with the chain carried and retained;
   - the rules of §5.3, including subordinate voids, with convergence vectors that
     cover missing keep lists;
   - retention of keep lists;
   - keep proofs in `records` for light readers (protocol v5).
3. **Tooling:**
   - per-agent keys in the node;
   - the cold root as the client default;
   - `first_seen`, `void --keep-before` with a drop list, keep manifests, and routine
     rotation.
4. **Succession v1:** rewrite mode, transition and GC.
5. **Later:**
   - verbatim carry;
   - stamps;
   - signed snapshots with a void index;
   - periodic seals with aggregation;
   - FROST owner keys;
   - the endpoint binding;
   - hidden recovery keys.

## 12. Implementation status (2026-11-12)

Implemented with the format (build order items 1 and most of 2):

- `Header.work` and the Logic 1 input `work`; `Header::mine`.
- `Void` v1: `cert | key`, `keep`, `before` and `work`.
  - Admission verifies the whole chain (signatures, database, linkage), the keep list
    (order, count, root, `maxKeepCount`) and `voidWork`.
  - A missing keep list leaves the void pending (`Reject::KeepMissing`).
- `Forward` as leaf kind 2, with `owner` and the `nextOwner` check.
- The genesis: a structured `predecessor`, `nextOwner`, `maxKeepCount` and `voidWork`.
- `endpoint?` in certificates.
- The reference index and `ledgerRoot` (§4.1), derived by each node.
- Resolution by §5.3: keep lists, `before`, key voids, and subordinate voids by
  rule (ii).
- Store schema 5: forwards, retained keep lists, `ref_root`, `ledger_root`.
- Protocol v5: keep lists travel with their voids, and forwards replicate.
- Vectors in `vectors/0004.json`. `vectors/core.json` is unchanged: every format 1
  record written before this design keeps its bytes and its id.

Tooling (item 3, in part):

- Per-agent keys in the node. A request with `agent` is signed by that agent's key
  (`home/agents/<name>.key`), under a certificate the device issues: the device's
  area, at most 30 days and never past the device's certificate, renewed in the last
  week when that extends it. The MCP server passes `SAMEROOT_AGENT`.
- `first_seen`: when the node first admitted each record, by its own clock.
- RPC `certs`, `void.plan` (kept and dropped entries by `first_seen`), `void.add` and
  `void.sign`; CLI `sameroot certs` and `sameroot void <cert> [--keep-before]
  [--before] [--total] [--owner] [--yes]`, which shows the plan unless given `--yes`.

Succession v1 (item 4), rewrite mode:

- `succession::rewrite` (core, pure) plans it from the cut. The child genesis keeps
  the name, owner, contract and limits and records `predecessor`. The owner signs the
  owner subspace's state anew at the child's `createdAt`, keeping expiries. Every
  carried device gets a certificate in the child, published at
  `.grants/<cert id>` (the §9 Q1 convention). The forward names the child, its owner
  and the cut. `follows` checks a child genesis against its forward.
- The node:
  - **Pin.** A node that sees a forward pins the successor and stops writing to the
    parent. Of several forwards it takes the one with the lowest id and reports a
    fork.
  - **Follow.** It asks the parent's peers for the successor. Once the successor's
    genesis matches the forward, the node follows: requests that name the parent (an
    id prefix in `SAMEROOT_DB` included) land in the successor unless they say
    `exact`. The parent is no longer dialed.
  - **Certificate.** The node installs its own certificate from the grants (checking
    the owner's signature). A node that wrote the parent under a certificate and has
    none in the successor refuses writes, instead of writing to its device's own
    subspace.
  - **Late entries** are those admitted after the forward, or dated after the cut.
    `late` lists them, and `late.resubmit` writes this device's own anew in the
    successor, skipping keys that have a newer entry there and negations.
  - **`gc`** retires the parent after the 14-day grace (`force` skips it). The store
    keeps only the stub: the genesis and the forwards under a trie of their own. Later
    admissions are refused.
  - **Blob GC.** iroh-blobs garbage collection then drops values no database
    references. It runs only once some database is retired.
- Sync: a retired database's `hello` carries its forwards, and the session ends there.
  A straggler admits them (after the genesis, if it had none) and follows.
- CLI: `sameroot owner succeed [--yes]` (the plan unless `--yes`), `sameroot late
  [--resubmit]` and `sameroot gc <db> [--force]`.

Since the review of 2026-11-15:
- A node follows a successor only once this device's certificate is in (if it wrote
  the parent under one) and the successor caught up with a peer, or after two
  minutes. Until then, requests keep going to the parent, which holds the whole
  state. A follow survives a restart.
- `late --resubmit` carries only entries that still count in the parent, oldest
  first, keeping their times.
- The owner's tool publishes the grants first and the forward last.
- Applications seal for the chain's origin (`status` reports it per database), so
  sealed values stay readable after a succession.

Limits of v1:
- Only the owner's subspace is carried. Strangers' subspaces in an open-write database
  are not.
- Grants go to the devices whose certificates the owner's node holds: those that
  wrote, and those in the database's own grants (a previous succession). The grants
  themselves aren't carried as values. Other devices need `owner delegate` in the
  child.
- The owner key and the memory key stay the same: rotation is a later step.
- The state of the cut travels in one RPC response (16 MiB).

Not yet: light-proof APIs over the reference index, keep proofs in `records` frames,
the cold root as the client default, routine rotation, entry proof of work in the
node's writes, verbatim carry, and key rotation at succession.

