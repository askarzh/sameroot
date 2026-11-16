# Design 0001: Sameroot architecture and format 1

Status: **revision 2, accepted direction** (2026-11-10), **amended by
[design 0003](0003-ledger.md)** (the ledger, 2026-11-11): where they differ, 0003
wins, and its §12 lists every amendment (the root over the ledger instead of the
winners, the contract instead of hard-coded presets, `readers` and replication
admission removed, plain-BLAKE3 values, protocol v3). Implemented: see 0003 §13.
Revision 1 was reviewed by Claude Fable 5.2 with Codex and Gemini; §20 lists what
changed and why. The owner accepted the review's recommendations on every open
decision (§19).

Inputs:
- the TypeScript implementation `denkmitdb/denkmitdb` (main a46e0ca): its specs
  (`ordering`, `delegation`, `succession`, `messaging`), `KNOWN_ISSUES.md` and the
  [November 2026 review](https://github.com/denkmitdb/denkmitdb/blob/main/docs/review-2026-11.md);
- an iroh spike on the live machines (2026-11-10, §12);
- the design review of revision 1 (2026-11-10).

## 1. Decisions already made

- **Rust, no JavaScript bindings.** One implementation, one binary per role.
- **New formats ("format 1").** No v4 compatibility; the v4 test network holds
  nothing of lasting value and is re-created, not imported (§17).
- **Platform first.** Sameroot is a database platform; agent memory and messaging are
  the first application, built on generic mechanisms.
- **New repository**, `denkmitdb/denkmit`, private until phase 1 lands (§19 Q9).

## 2. Goals and non-goals

Goals:
1. **The core guarantee:** every record is attributable to a key; every replica
   checks signatures, delegation and the database's own rules before keeping
   anything; no operator can forge, alter or reorder.
2. **Convergence by construction:** whether an entry is acceptable is a pure
   function of the genesis, the entry's signed header and its verified certificate
   chain — never of what a replica has already accepted or of its clock (§9).
3. **Fix by design what v4 fixed by patching:** database binding, no identity fetch
   before authorization, no global ordered tree, bounded work per peer.
4. **Built in from the start:** owners and delegation, value limits, retention
   without resurrection, replication admission, a change feed.
5. **Portable by construction:** normative spec plus language-neutral conformance
   vectors from the first commit.
6. **Reachability:** direct connections where the network allows, relays where it
   doesn't, including networks that allow only TCP 443.

Non-goals: queries and secondary indexes in the core, rich CRDT merges,
transactions, compare-and-swap, BFT agreement, **equivocation protection** (a writer
can show different entries to different peers until they sync), hiding who talks to
whom, semantic search in the core, quotas over a writer's total (they can't
converge; §9.3).

## 3. Threat model

| Actor | Can | Cannot |
|---|---|---|
| Outsider (knows an address or invite) | Try to connect | Read or write: admission (§13) refuses non-members |
| Member writer | Write within its rules and limits; fill its own subspace up to structural limits; grind ties | Forge others' entries, write outside its authority, change rules |
| Malicious seed (a member that stores and forwards) | Withhold, delay, observe keys, sizes, writers, times and unencrypted values | Forge, alter, reorder; read encrypted values |
| Transport relay | See which endpoints talk, and when | See content (QUIC is end-to-end encrypted) |
| Stolen device or agent key | Sign within its certificate's scope and window, including backdated entries inside the window | Overwrite newer data (LWW); survive voiding of its certificate (§7.4) |
| Stolen owner key | Everything the owner can | — remedy is succession to a new database (§10) |
| Other users of the same OS account | Use the node's sockets and keys | — the security boundary is the OS user |

## 4. Layers and crates

```
sameroot-core   pure, sans-I/O: canonical encoding, identities, headers, genesis,
               certificates, rule evaluation, LWW, reconciliation logic
sameroot-store  storage trait + redb implementation: entries, values, index,
               certificates, voided set; emits winner-change events
sameroot-sync   replication protocol over an abstract bidirectional stream
samerootd       the node: keystore, databases, iroh endpoint, relays, journal,
               local RPC
sameroot-mcp    agent application: MCP server (rmcp) over the node's local RPC
sameroot        CLI: init, status, invite/join, get/set/list, owner tools, contacts
```

`core` knows nothing about networks or applications; `sync` takes a stream, not
iroh; only `samerootd` wires iroh in.

## 5. Encoding and hashing

**CBOR profile (frozen).** Deterministic CBOR, restricted further than dag-cbor:
text-string map keys only (so RFC 7049 and RFC 8949 orders coincide), integers up
to 64 bits, definite lengths, no tags, no floats, no duplicate keys, no trailing
bytes, nesting depth ≤ 16. A decoder re-encodes every input and **rejects it if the
bytes differ**; signatures and hashes are checked over the bytes as received.

**Hashing.** BLAKE3-256 with a **derive-key context per object type**
(`"sameroot 1 entry"`, `"sameroot 1 genesis"`, `"sameroot 1 cert"`, `"sameroot 1 value"`,
`"sameroot 1 void"`), so one type's hash can never be presented as another's. Signed
objects contain raw 32-byte digests; CIDs (BLAKE3 multihash `0x1e`) are only a
display and export form. Note: BLAKE3 and ChaCha20 are not FIPS-approved.

## 6. Identities

- **Identity = an Ed25519 public key.** Self-certifying: nothing has to be fetched
  before a signature can be checked.
- **Verification is pinned:** strict cofactorless verification — canonical `S`,
  canonical encodings of the public key and `R`, small-order public keys and `R`
  rejected, no batch verification (`verify_strict` in ed25519-dalek). The published
  edge-case vectors are part of `vectors/`. "Ed25519 (RFC 8032)" alone is not a
  specification: libraries disagree, and a disagreement splits replicas.
- **Signatures are over a typed id**, never over raw payloads: every signed object
  has an id `BLAKE3_derive(context, canonical bytes of the unsigned object)` and the
  signature is over that 32-byte id. The context provides domain separation without
  prefix ambiguity.
- **Owner keys stay out of the node.** The owner key lives in an offline tool, a file
  or a hardware token, and signs device certificates. Nodes hold device keys; agent
  keys are held by the node under device-issued certificates.
- **Encryption keys are separate** X25519 keys published in the identity's card
  (§11), with rotation; old private keys are kept for decryption.
- **Transport keys are separate:** an iroh EndpointId is not a database identity. A
  card may bind "device key D runs endpoint E".
- **Limit, stated:** an owner key is the identity forever. Its loss or theft has no
  remedy except succession to new databases.

## 7. Delegation

### 7.1 Certificate

```
Cert = Signed<{
  v: 1,
  issuer: PublicKey,
  subject: PublicKey,
  parent?: CertId,           // absent: the issuer is the root (an owner)
  db: DatabaseId,            // required; "any database" only as an explicit,
                             // non-default exception, never produced by tooling
  area: { subspace: Subspace, pathPrefix: [component], ops: [put|delete|deletePrefix|read] },
  window: { notBefore: u64, notAfter: u64 },   // milliseconds
  name?: string              // e.g. "lab", "codex"; for display only
}>
```

- **Authority is the conjunction of every link:** an entry is authorized if it lies
  inside the area and window of every certificate on the chain from the leaf to the
  owner. No "narrowing proof" is needed, so any structured restriction composes.
- Chain depth ≤ 3 (owner → device → agent), each certificate ≤ 4 KiB, verification
  cached by leaf id.
- Semantics follow Meadowcap's areas (subspace × path prefix × time range); the
  format is our own. UCAN brings no ecosystem we need.

### 7.2 Entry ↔ certificate

An entry carries only the **leaf certificate id**. Certificates are immutable blocks
named by id: a peer that offers an entry must serve its chain on request (§12.3).
Reconciliation re-offers anything still missing, so "entry before certificate"
needs no durable pending set.

### 7.3 Windows bound timestamps

A delegated entry must satisfy `notBefore ≤ ts < notAfter` for every link. Short
windows, renewed by the node, are the deterministic bound on how far a delegate can
date entries. Day-to-day writes should be delegated; rules may restrict what an
owner key signs directly.

### 7.4 Revocation by voiding

`Void = Signed<{ v: 1, db, cert: CertId }>`, signed by the certificate's issuer or
an ancestor. Voids form a **grow-only set**; every entry whose chain contains a voided
certificate is removed, whatever its timestamp. The verdict depends on replicated
state, but only monotonically, so replicas converge. The legitimate device re-signs
its live data under a new certificate.

- Use in single-owner subspaces: in a shared subspace, voiding can reveal an older
  entry that some replicas already dropped.
- Expiry never bounds a compromise: a stolen key can keep signing entries dated
  inside any window it held. Voiding does; owner-key compromise needs succession.

## 8. Entries

### 8.1 Signed header, detached value

```
Header = {
  v: 1,
  db: DatabaseId,
  subspace: Subspace,        // an owner's PublicKey, or the reserved shared subspace
  path: [bytes],             // ≤ 16 components, each ≤ 255 bytes, total ≤ 1 KiB
  op: put | delete | deletePrefix,
  ts: u64,                   // writer's clock, milliseconds
  exp?: u64,                 // required when the genesis sets maxTtl (§10.1)
  valueSize: u64,            // 0 for deletes
  valueHash: Digest,         // BLAKE3 "sameroot 1 value"; zero digest for deletes
  signer: PublicKey,
  cert?: CertId              // leaf certificate; absent if signer == subspace owner
}
EntryId = BLAKE3_derive("sameroot 1 entry", canonical(Header))
SignedEntry = { header: Header, sig: Ed25519(signer, EntryId) }
```

- **The value is not inside the signed object.** Rules, reconciliation and
  verification work on the header alone; the value is fetched by hash and checked
  against `valueHash` and `valueSize`. "Inline or blob" is a transport detail: small
  values travel in the same sync message, large ones over the blobs protocol.
- **Subspace as a field:** the owner of the data is explicit. One owner's devices and
  agents share its subspace, and keys of different owners can never collide. This
  replaces the v4 `agents/<cid>/` prefix convention. The **shared subspace** is
  reserved for databases whose rules let several owners write the same keys.
- **Paths of components**, not strings: no separator ambiguity, Willow-compatible
  shape. Applications use UTF-8 components by convention.
- **Values are opaque bytes**; applications choose their encoding.
- Grinding: a signer can produce many headers (and ids) for one value by varying
  `ts`; tie-breaking by `EntryId` is therefore under the signer's influence. Stated,
  accepted.

### 8.2 Ordering and conflicts

- **Per-key last-writer-wins on `(ts, EntryId)`** within `(subspace, path)`.
- `deletePrefix` hides every entry in the same subspace under the path prefix with a
  smaller `(ts, EntryId)`, and replaces their individual tombstones. It is explicit;
  an ordinary `put` never deletes other keys (unlike Willow's implicit pruning).
- **No global ordered tree:** an entry's timestamp only affects its own key.
- **Future timestamps are deferred, not judged:** a replica doesn't store or relay an
  entry with `ts > now + tsSkew` (genesis parameter) until its clock passes.
  Reconciliation re-offers the entry later; a bounded negative cache avoids repeated
  transfers. This is local admission policy, never a consensus rule.
- Honest writers set `ts = max(now, currentWinner.ts + 1)` — but only if the current
  winner is within `tsSkew` of the local clock, so one future-dated entry can't drag
  every writer's clock forward.

## 9. Database genesis and rules

### 9.1 Genesis

```
Genesis = Signed<{
  v: 1,
  nonce: bytes(16),          // two otherwise equal databases get different ids
  createdAt: u64,
  name: string,
  owner: PublicKey,          // signs the genesis; the succession authority (§10.2)
  rules: { language: 1, access: Rule, validity: Rule },
  readers: ReaderPolicy,     // §13
  limits: { maxValue, maxPath, tsSkew, maxTtl? },
  predecessor?: DatabaseId,  // §10.2
  meta?: map
}>
DatabaseId = BLAKE3_derive("sameroot 1 genesis", canonical(unsigned genesis))
```

### 9.2 Rule language

"Sameroot Logic": a closed, total, deterministic expression language over CBOR values
(the v4 JsonLogic subset, re-encoded), versioned by `rules.language`, with a hard
evaluation budget (depth, steps, size) and no type coercion. A rule can read
**only**:

- genesis fields;
- header fields: `op`, `subspace`, `path`, `ts`, `exp`, `valueSize`, `valueHash`,
  `signer`;
- facts from the verified chain: `owner` (chain root), `chain` names, the leaf
  certificate's area and window.

Nothing else: no counters, no "previous entries", no clock. Expressible: write
authority per subspace, path shapes, value limits, immutable keys (`valueHash`
equals a path component), put-only areas, allowlists of owners. CEL stays a candidate
for a later `language` version.

### 9.3 Limits that converge, and what stays local

| In consensus (pure) | Local policy (never claims equal state) |
|---|---|
| Path shape and size, value size, `maxTtl`, certificate windows, key shapes that bound live entries per writer (LWW per key) | Storage and rate budgets per owner, per peer, per database and node-wide; future-timestamp deferral |

A replica that refuses data because of a local budget reports itself **incomplete**
for that owner; it never claims to hold the same state as its peers.

Removed in revision 2 (they don't converge — counterexamples in the review): per-writer
entry and byte counters, "count only live entries", a timestamp window relative to a
writer's previous entries, and per-certificate quotas.

### 9.4 Presets

Presets compile to rules. Default `own-subspace`: the signer must be the subspace owner
or hold a chain rooted at it; the shared subspace is closed. Others: `allowlist`
(listed owners only), `shared-allowlist` (listed owners may write the shared
subspace), `put-only` (no deletes).

## 10. Retention and succession

### 10.1 Retention without resurrection

v4-style "drop tombstones after a local window" lets anyone resurrect deleted data by
replaying an archived signed put. Format 1 offers two sound modes, chosen in the
genesis:

1. **Expiring database** (`maxTtl` set): every entry carries `exp` with
   `ts < exp ≤ ts + maxTtl` — a pure rule. Replicas refuse and drop entries past `exp`.
   A tombstone can be dropped after `ts + maxTtl + tsSkew`: every put it hides has
   expired by its own signed fields. Long-lived values are re-signed before they
   expire (the node does this for its own keys); data of departed writers
   disappears.
2. **Permanent database** (no `maxTtl`): tombstones are kept forever; growth is
   bounded by `deletePrefix` and, eventually, by succession.

Superseded entries are local history only and may be dropped at any time; they are
never needed for convergence.

### 10.2 Succession

The genesis is immutable, so it can't name its successor. Instead: the **successor**
names its predecessor in `predecessor`, and the predecessor's owner writes a signed
**forward record** into the old database. Clients follow it. The owner is the
succession authority. Entry binding (`db` in every header) makes replay into the
successor impossible.

## 11. Cards, contacts and messages (platform conventions)

These are carried over from the TypeScript `specs/messaging.md`: a reserved `_/`
path component, tolerant readers, canonical digest strings, and addresses never
stored in data.

- **Card:** `[_ , card]` in the identity's subspace, written by a device-level key:
  handle, device, role, X25519 encryption keys, endpoint bindings, what it accepts.
- **Messages:** `[_, outbox, <recipient>, <id>]` in the sender's subspace;
  `inReplyTo` by EntryId; optional receipts. They are records: no queue, no delivery
  guarantee.
- Only device-level certificates may write under `_`; agents write through the node.
- **Contacts** stay local, changed only by a person.

## 12. Replication

### 12.1 The reconciled set

For each database: **one current winner per `(subspace, path)`** (a put or a
tombstone) that hasn't expired, ordered by `(subspace, path)`, each identified by its
`EntryId`. Item lists carry `(subspace, path, ts, EntryId, valueSize)` as hints, so a
receiver can skip an offer that loses to its own winner without fetching it. Every
fetched entry is verified. Reconciliation computes the LWW join, not a set union.
Each session runs against a storage snapshot; live updates queue behind it.

Not in the set: superseded history (local), values (fetched by hash), certificates
and voids (served as dependencies; voids are also exchanged as their own small
grow-only set).

### 12.2 Range-based set reconciliation

Peers exchange fingerprints of key ranges, split ranges that differ, and exchange the
missing entries: the approach of Willow, iroh-docs and Negentropy. Cost grows with
the difference, not with the database.

**Fingerprints are negotiated in the sync handshake and are not part of format 1.**
Version 1 is a **per-session keyed sum**: both peers contribute a nonce, and a range's
fingerprint is the sum of `BLAKE3_keyed(sessionKey, EntryId)` plus the count. A
plain sum or XOR of hashes is attackable by any writer who grinds ids (generalized
birthday attack; reported at about 28 hours on 8 cores for Negentropy's
construction). A canonical BLAKE3 hash trie or a multiset hash are the candidates for
a later version, when databases grow past about a million entries or signed heads
are needed.

### 12.3 Sync protocol

- **Handshake:** protocol version, fingerprint version, admission proof (§13),
  per-session limits.
- **Per database:** reconciliation rounds; on request, certificates and voids for
  offered entries; small values inline, larger values over the blobs protocol.
- **Live updates:** after the first round the stream stays open and new accepted
  entries are pushed. This is the change feed (§14) on the wire; it replaces pubsub.
- **Verification on receipt:** decode (re-encode check), check the signature, check
  `db`, verify the chain and voids, evaluate the rules, then store. Unsigned metadata
  is never trusted.

### 12.4 Denial of service

| Attack | Bound |
|---|---|
| Many tiny or overlapping ranges | Ranges disjoint and strictly subdividing; caps on depth, ranges per message, work per session |
| Forced recomputation | Per-session cost budget; sessions per peer rate-limited |
| Repeated offers that are always refused | Bounded negative cache by `EntryId` with reason and retry time; disconnect on no progress |
| Bogus certificate chains | Depth ≤ 3, ≤ 4 KiB each, verify budget per peer, cache by leaf id |
| Lying about value size | Signed `valueSize` checked against genesis limits before fetching, enforced while streaming |
| A member filling disks | Structural limits plus local budgets (§9.3) |
| Many databases or identities | Node-wide budgets as well as per-peer and per-database ones |

## 13. Replication admission (read control)

- The genesis declares a **reader policy**: `public`, or a list of owner keys, plus
  certificates with the `read` op (so a seed can be admitted as a reader without
  being a writer). It is **not derived from the write rule**: under `own-subspace` any
  new key may write its own subspace, so that would admit everyone.
- **Channel-bound mutual proof:** each side signs a fresh challenge containing the
  database, protocol version, both EndpointIds and the roles. Both sides prove
  membership (the dialer pushes entries too). "Unknown database" and "not
  authorized" get the same answer.
- The **blobs protocol is gated** the same way.
- What it is: honest nodes replicate only to proven members, so a leaked address or
  invite no longer leaks the database. What it isn't: confidentiality. Members, or a
  stolen member device, can copy data, and removing a reader retracts nothing.
  Confidentiality is §15.
- All-or-nothing per database in format 1.

## 14. Node, change feed and local API

- **Change feed:** the store emits an event whenever a key's live winner changes
  (origin `local`, `remote` or `restore`); the node keeps a durable journal with
  cursors on top. Messages, hooks and MCP notices build on it.
- **Local API:** a native RPC (length-prefixed CBOR frames over owner-only Unix
  sockets), with a version handshake, cancellation, back-pressure, and stream
  semantics for the change feed. It isn't part of the format 1 spec: it's local and
  may change per release. One socket is bound to one identity. Socket ownership
  authenticates an OS user, not an agent.
- **MCP lives in `sameroot-mcp`**, one process per agent session, so MCP revision
  churn stays out of the node (rmcp went from 3.5.0 to 3.9.0 in six weeks), and a
  node restart doesn't break agent sessions.
- **Several databases per node** from the start.

## 15. Encryption of values

- **HPKE** (RFC 9180) base mode per recipient, wrapping one content key. The default
  suite is X25519 + HKDF-SHA256 + ChaCha20-Poly1305; an explicit `suite` field allows
  post-quantum suites later (ciphertexts sit on seeds for years: harvest now,
  decrypt later).
- **Sender authentication comes from the entry signature:** readers verify the entry
  first.
- **Key commitment:** ChaCha20-Poly1305 isn't key-committing, so the envelope
  contains a commitment to the content key. Otherwise one signed entry could decrypt
  to different values for different recipients.
- **Large values:** chunked AEAD with the chunk index and a final-chunk flag.
- The AAD binds `db`, `subspace`, `path` and `signer`.
- No forward secrecy for stored values. Stated.

## 16. Storage and keystore

- **redb** (4.5.0) behind the storage trait: entries by id, the live index by
  `(subspace, path)`, certificates, voids, the negative cache, the journal and values.
  redb major versions have changed the file format, so the store carries its own
  schema version and an upgrade path.
- The **index is persisted**: reopening doesn't re-verify every entry.
- **Keystore:** Argon2id (parameters fixed in the spec) + XChaCha20-Poly1305, atomic
  updates, old X25519 keys retained. The passphrase comes from the OS keychain or a
  systemd credential, not an environment variable.

## 17. Migration from v4

None. The v4 test network holds about 80 test records of no lasting value, and
re-signing them would forge authorship. The four machines are re-created on Sameroot
at the switch-over. The TypeScript node keeps running until then.

## 18. Conformance and testing

- `spec/`: normative text for the CBOR profile, every object type, verification,
  rules, LWW, retention, admission and the sync protocol.
- `vectors/`: canonical bytes (hex), ids, signatures (including the Ed25519 edge
  cases), rule evaluations, LWW and `deletePrefix` outcomes, expiry, voiding,
  reconciliation rounds. Generated once by the reference implementation, checked in,
  never regenerated to make a test pass.
- Decoder fuzzing (cargo-fuzz), property tests for convergence with random delivery
  order, deterministic simulation of multi-node networks (turmoil), then real iroh
  endpoints.
- A correspondence table to Willow's data model and Meadowcap is kept in the spec, so
  that a translation stays mechanical.

## 19. Decisions (2026-11-10, owner accepted the review's recommendations)

1. **Hash:** BLAKE3-256 with a derive-key context per object type; raw digests inside
   signed objects, CIDs for display only.
2. **Delegation:** our own minimal certificates with Meadowcap-shaped semantics
   (§7); not UCAN.
3. **Per-writer counters:** removed; structural limits and local budgets instead
   (§9.3).
4. **Namespace:** keyed by owner, as the `subspace` entry field (§8.1), not a path
   prefix.
5. **Local API:** native RPC plus a separate `sameroot-mcp` process (§14).
6. **Storage:** redb behind the storage trait (§16).
7. **Restricted networks:** our own iroh relay on 443 behind the existing TLS proxy,
   using the OS trust store (`platform-verifier`) and proxy support
   (`proxy_from_env`). A WebSocket adapter for sync gets built only if that fails; it
   would need its own authenticated encryption (Noise).
8. **Read control:** in format 1, as an explicit reader policy with `read`
   certificates and a channel-bound mutual proof (§13).
9. **Repository:** private until phase 1 lands (spec, vectors, core); then public,
   after removing host and network details from the documents.

Still open, to settle during phase 2: the fingerprint version after the keyed sum
(trie, which Codex and Gemini prefer, or multiset hash); a written proof and property
test before any newest-N eviction is adopted.

## 20. Changes from revision 1

| Revision 1 | Revision 2 | Why |
|---|---|---|
| Rule inputs included per-writer counters; timestamp window relative to the writer's entries | Pure rule inputs only (§9.2); future timestamps deferred locally (§8.2) | Order-dependent acceptance doesn't converge (review §1.2, counterexamples) |
| Local tombstone retention window | Signed expiry under genesis `maxTtl`, or permanent tombstones (§10.1) | Replay of an archived put resurrects deleted data |
| Additive BLAKE3 fingerprint in the format | Negotiated per session; v1 keyed sum (§12.2) | Generalized birthday attack by any writer |
| Value inside the signed entry | Signed header with `valueHash`/`valueSize`; value detached (§8.1) | Rules, sync and verification never need value bytes |
| Owner as a key prefix preset | `subspace` field; paths of components (§8.1) | Owner explicit, agents of one owner share it, no separator ambiguity |
| Membership proof derived from the write rule | Explicit reader policy, `read` certs, channel-bound mutual proof (§13) | Under `own-subspace` everyone would be "a writer" |
| Ed25519 per RFC 8032; string domain prefixes | Strict verification pinned; signatures over typed ids (§6) | Library disagreement splits replicas; prefix ambiguity |
| Certificate "replicated like entries"; full chain in entry; per-cert quotas | Certificates as dependency blocks, leaf id in entry, conjunction of links, voiding (§7) | Undefined distribution; narrowing undecidable; quotas don't converge |
| Genesis without nonce; "names a successor" | Nonce; successor names predecessor + forward record (§9.1, §10.2) | Equal databases collided; an immutable genesis can't point forward |
| HPKE without commitment | Key commitment, chunking, `suite` field (§15) | Non-committing AEAD; long-lived ciphertexts |
| `import-v4` | No migration (§17) | 80 test records aren't worth it |
| Delegation in phase 4 | Delegation and header in phase 1, admission in phase 3 (§21) | Formats depend on them |

## 21. Phases and effort

Estimates are full-time weeks for one developer with AI assistance (review
estimate; Codex 28–45, Gemini 18). The spec and vectors, not the code, are the long
pole.

| Phase | Content | Weeks |
|---|---|---|
| 0 | This revision accepted; `spec/` skeleton; crate workspace | 1 |
| 1 | `core`: CBOR profile, identities, header, genesis, certificates and chain verification, voids, rules, LWW, `deletePrefix`, expiry, vectors | 5–7 |
| 2 | `store` + `sync`: redb store, change feed, reconciliation, certificate transfer, negative cache, property and simulation tests | 6–9 |
| 3 | `samerootd`: iroh endpoint, own relay on 443, admission handshake, keystore, local RPC, CLI — **milestone** | 4–6 |
| 4 | Owner tooling, cards, encryption, journal, messages | 5–8 |
| 5 | `sameroot-mcp`, hooks, four-machine mesh, switch-over from v4 | 3–4 |
| 6 | Release: packaging for Linux x64/arm64 and macOS arm64, fuzzing, soak, documents, outside review | 3–5 |
| | **Total** | **27–41** |

**Milestone (end of phase 3):** two `samerootd` nodes — one of them the laptop on the
TCP-443-only network, reaching the other through our own relay — sync one database
with writes delegated from an owner to a device, one concurrent conflict and one
delete; both restart; both report the same full-set fingerprint. The same scenario
passes as a three-replica property test with random delivery order. No MCP,
encryption, cards, messages or custom rules.

**Walking skeleton option:** cut phases 1–3 to preset rules only and no admission
handshake to reach the milestone in about 8–10 weeks, then fill in.

**Resolved risk (2026-11-11):** iroh's relay path works from the TCP-443-only
network (no outbound UDP, no proxy) with our own relay: iroh-relay 1.4.1 behind
Caddy at `relay.example.org`, the node trusting the OS certificate
store (`platform-verifier`). The laptop's prototype node joined through it in under
3 s, and the three machines (Linux arm64, Linux x64 and the laptop) converged on the
same state, both directions. The spike's failure with n0's public relays is
explained by that configuration, not by the network. Decision 7's WebSocket adapter
is not needed.

## 22. Crates (versions on 2026-11-10)

| Purpose | Crate |
|---|---|
| Transport, relay | `iroh` 1.4.1 (features `platform-verifier` + a TLS backend), `iroh-relay` 1.4.1 (`server`) |
| Values | `iroh-blobs` 0.104.x; open serving since design 0003 (protocol v4) |
| MCP | `rmcp` 3.9.0 |
| Storage | `redb` 4.5.0 |
| Signatures, curves | `ed25519-dalek` 3.0.0 (`verify_strict`), `x25519-dalek` 3.0.0, `curve25519-dalek` 5.0.0 |
| Hash | `blake3` 1.8.7 |
| HPKE, AEAD, KDF | `hpke` 0.15.1 (`x25519`, `chacha`, `hkdfsha2`), `chacha20poly1305` 0.11.0, `argon2` 0.6.0, `zeroize` |
| Keychain | `keyring` 4.2.0 |
| CBOR | `minicbor` 2.3.1 with explicit codecs and the re-encode check |
| Reconciliation | our own, sans-I/O (references: `negentropy` 0.5.3, iroh-docs `ranger.rs`) |
| Tests | `proptest` 1.12.0, `turmoil` 0.7.2, cargo-fuzz |
| Fallback transport (only if needed) | `tokio-tungstenite` 0.30.0, `rustls-platform-verifier` 0.7.1, `snow` 0.10.0 |
