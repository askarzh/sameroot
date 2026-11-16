# Sameroot specification, format 1

Normative description of Sameroot's formats and protocols, written so that an
independent implementation in any language can interoperate with this one. The key
words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

Status: **skeleton**. Each file is filled in as format 1 freezes, together with its
vectors. Until then the designs are normative: [design 0003](../docs/design/0003-ledger.md)
(the ledger, the contract, protocol v3) and, where 0003 doesn't amend it,
[design 0001](../docs/design/0001-architecture.md). Two files changed scope with 0003:
replication admission is gone (the platform is open; 08 will describe the local
serving policy), and encryption is application-level (09 will describe the sealed
value format of `sameroot-seal`, see [docs/mcp.md](../docs/mcp.md)).

| File | Contents | Source |
|---|---|---|
| [01-encoding.md](01-encoding.md) | Encoding and hashing | design §5 |
| [02-identities.md](02-identities.md) | Identities and signatures | design §6 |
| [03-certificates.md](03-certificates.md) | Delegation certificates and voids | design §7 |
| [04-entries.md](04-entries.md) | Entries | design §8.1 |
| [05-genesis-and-rules.md](05-genesis-and-rules.md) | Genesis, the contract, Sameroot Logic 1 | 0003 §5 |
| [06-ordering-and-retention.md](06-ordering-and-retention.md) | The ledger trie, resolution, negations, expiry | 0003 §4–§6 |
| [07-sync.md](07-sync.md) | Replication protocol v3 | 0003 §7, §13 |
| [08-admission.md](08-admission.md) | Serving policy (replication admission is removed) | 0003 §5.1 |
| [09-encryption.md](09-encryption.md) | Sealed values and hidden names (application level) | docs/mcp.md |
| [10-conventions.md](10-conventions.md) | Platform conventions: cards and messages | design §11 |

Not part of the specification: the node's local RPC, the CLI, and the MCP application
(they are local and may change in any release).
