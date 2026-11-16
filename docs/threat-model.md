# Threat model

What Sameroot protects, from whom, and what it doesn't. This is a prototype without an
independent security review. Read this page before you put anything sensitive in it.

## In one paragraph

Records are signed, and every node enforces the database's rules, so nobody can forge
or slip in a record the rules don't allow. **Reading is not restricted:** anyone who
knows a database's id and can reach a node that holds it can copy the whole database:
every record, every certificate, every value. Confidentiality is the application's
job. The agent memory encrypts values and hides key names, but **metadata stays
visible**: who wrote, when, how much, and which certificates exist.

## What each party can see and do

| Who | Can | Can't |
|---|---|---|
| **Anyone who knows a database id** (and reaches a node holding it) | Replicate it all: record headers (subspace, path, op, time, value size and hash, signer, certificate id), certificates (issuer and subject keys, **names**, validity, rights), voids and forwards; fetch values by hash | Write where the rules don't allow it; forge or change a record; read sealed values or hidden names without the memory key |
| **Anyone at all** | Fetch a value by its hash from any node that holds it (values are served openly, as in IPFS) | Find a hash they don't already know; read a sealed value |
| **A relay** | See that two endpoints talk, when, and how much; drop or delay traffic | Read or change it: iroh traffic is end-to-end encrypted (QUIC) |
| **A malicious peer** | Withhold records, so you see an older state until an honest peer delivers them; send invalid records, which every node rejects; send forged tree nodes, which aren't walked; load a node within its limits (sessions, timeouts, outbox, fetches) | Make an invalid record count; make a node want records outside the root it announced |
| **A stranger in an open-write database** (rules that let any key write its own subspace) | Write in their own subspace, which is listed apart by default | Write in someone else's subspace |
| **A delegated device or agent** | Write within its certificate's rights until it expires or is voided; read whatever its memory key opens | Write outside its rights; void certificates above it |
| **Whoever holds the owner key** | Everything: delegate, void any certificate, start a successor | Change what other nodes already hold |

## Keys

- **Owner key.** The root of a database's authority. Keep it on one machine and back it
  up. A thief can delegate itself, void your devices and, unless the genesis committed to
  the next owner (`nextOwner`), publish a successor. There is no recovery from a lost
  owner key yet.
- **Device and agent keys** sign writes. A leaked one is voided with `sameroot void
  <cert> --keep-before <time>`. Its entries that this node saw before that time keep
  counting, and the later ones stop. The time a node first saw a record is its own
  clock, which the thief doesn't control (design 0004 §5).
- **Memory key** (agent memory): one symmetric key per memory, shared by the owner's
  devices. Whoever has it reads everything in the memory. There are no per-agent read
  scopes yet. Revoking a writer doesn't take back what it could read: a leaked memory
  key needs a new key and re-encrypted data, and rotating the key isn't built yet.
- **Endpoint key**: the node's network identity. A relay may allowlist it.

## Time

A record's time is set by its signer. Nodes hold back records dated more than the
database's skew ahead (10 minutes by default) until their time comes. A signer can
backdate within its certificate's validity, which is why revocation keeps by first-seen
time, not by the claimed one.

## Ids and invites

- A database id is effectively a **read capability**. Share it, or an invite that
  contains it, only with whom may read the database's metadata and sealed values.
- The stub of a collected database hands its successor's id to anyone who asks with the
  old id.
- Invites also carry a node's endpoint id and addresses.
- Use throwaway databases in demos, screenshots and bug reports.

## Not protected

- **Metadata** (above), and traffic analysis.
- **Availability:** a node that holds the only copy of a record can withhold it. Peers
  can't tell what they never received.
- **Deletion:** nothing is ever deleted from a database. A succession leaves the old one
  behind as a stub, but only on the nodes that collect it; copies elsewhere stay.
- **Forward secrecy** for sealed values.
- **Finality:** a late record can still change a value until every node has it.

## Primitives

Ed25519 signatures (strict verification), BLAKE3 with domain separation for ids and
trees, canonical CBOR. Sealed values use XChaCha20-Poly1305 with associated data binding
the succession chain's origin and the path. Hidden names are keyed BLAKE3 MACs. The
transport is iroh (QUIC, TLS 1.3).

Report security problems as described in [SECURITY.md](../SECURITY.md).
