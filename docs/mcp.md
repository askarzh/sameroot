# Shared memory for agents: `sameroot-mcp`

`sameroot-mcp` is an MCP server (stdio) over the local Sameroot node. Every agent on
every machine whose node replicates the same database sees the same memory. A
write is a signed ledger record, pushed to the other nodes at once: on the
prototype mesh it is readable 30 ms later on a nearby server and 90 ms later
across a 111 ms link.

**Values and key names are encrypted.** The ledger is readable by every node, so
the memory seals each value and hides each key name with the owner's memory key (see
Encryption). Signed headers stay readable: who wrote, when, value sizes, and the
depth of a key. Don't store credentials.

## Tools

| Tool | Arguments | Result |
|---|---|---|
| `memory_status` | — | Device, databases (records, root, peers), selected database, encryption key id |
| `memory_set` | `key`, `value` (any JSON) | The record id and time, `encrypted` |
| `memory_get` | `key` | `found`, `value`, `encrypted`, `signer`, `ts`, `id` |
| `memory_list` | `prefix`, `limit` (default 100, at most 1000), `after` (the previous `next`), `keys_only` | `count` (all keys), `items` (one page, in key order), `next` |
| `memory_delete` | `key` | A signed tombstone (the ledger keeps the record) |
| `memory_provenance` | `key` | Who wrote the current value, when, and its id |

Keys are paths (`notes/topic`, `tasks/42`). Values are JSON, sealed before storage.

## Configuration

- `SAMEROOT_HOME`: the node's home (default `~/.sameroot`).
- `SAMEROOT_DB`: the database id or a prefix of it. Required when the node holds
  more than one database.
- `SAMEROOT_MEMORY_KEY`: the memory key file (default `$SAMEROOT_HOME/memory.key`).
- `SAMEROOT_AGENT`: this agent's name (`a-z`, `0-9`, `-`, `_`; e.g. `claude`, `codex`,
  `agy`). The node signs the agent's writes with a key of its own under a certificate
  from the device, so one agent can be revoked alone (`sameroot void <cert>`). Without
  it, writes are signed by the device.
- `SAMEROOT_PLAIN_NAMES=1`: store key names as they are (values stay sealed).
- `SAMEROOT_ALLOW_PLAINTEXT=1`: without a key, write unsealed values instead of
  refusing.

After a succession (`sameroot owner succeed`), `SAMEROOT_DB` may keep naming the old
database: the node sends its requests to the successor it follows.

## Encryption

Application-level, as the vision puts it: the platform serves anything to anyone;
the memory seals what it stores (`crates/sameroot-seal`).

- **Bound to the database's lineage:** a sealed value names the first database of
  its succession chain, the origin, which the node derives from the geneses. Values a
  succession carries stay readable in the successor, and every client of the chain
  seals alike, whichever member `SAMEROOT_DB` names. A node that holds only a
  successor, without its predecessors, can't name the origin and refuses to seal.
- **Key:** 32 random bytes in a file with mode 0600, the same on all of the owner's
  devices. Create it once with `sameroot-mcp keygen`, copy it to the other devices
  over a secure channel (`scp`, never chat), and keep a backup. `sameroot-mcp key-id`
  prints its id.
- **Cipher:** XChaCha20-Poly1305 with a random 24-byte nonce per value. Equal values
  give unrelated ciphertexts, so their hashes reveal nothing.
- **Format:** `"SRS1" ‖ key id (8) ‖ nonce (24) ‖ ciphertext and tag`. The
  associated data binds a value to its database and key name: copied elsewhere, it
  doesn't open.
- **Reading:** a sealed value opens with the key. Without it, `memory_get` reports
  `{"sealed": true, "readable": false}`, and the CLI shows `[sealed · key … · N bytes]`.
  Values written before encryption still read as plaintext.
- **Writing without a key** is refused unless `SAMEROOT_ALLOW_PLAINTEXT=1`.
- **Hidden names:** a key such as `notes/topic` is stored at `~/<t1>/<t2>`. Each token
  is a keyed BLAKE3 MAC of the component and the tokens before it (128 bits, base32,
  under a subkey of the memory key). The real name travels inside the sealed value
  (`{"$sameroot": 1, "key": …, "value": …}`). The same name gives the same tokens on
  every device with the key, so `memory_get` and prefix listings (whole components:
  `notes/`) work as before. Keys written before names were hidden are still found
  under their plain names.
- **Not hidden:** signers, times, value sizes, the depth of a key, and which keys
  share a parent (they share a token prefix). Key rotation is a next step.

## Registering

Claude Code (user scope):

```
claude mcp add --scope user sameroot -e SAMEROOT_HOME=$HOME/sameroot-proto/home -e SAMEROOT_DB=<db> -- $HOME/sameroot-proto/bin/sameroot-mcp
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.sameroot]
command = "/home/<user>/sameroot-proto/bin/sameroot-mcp"
env = { SAMEROOT_HOME = "/home/<user>/sameroot-proto/home", SAMEROOT_DB = "<db>" }
```

Antigravity CLI (`agy`):

```
agy mcp add -e SAMEROOT_HOME=$HOME/sameroot-proto/home -e SAMEROOT_DB=<db> sameroot $HOME/sameroot-proto/bin/sameroot-mcp
```

(Flags go before the name; `agy mcp list` shows it.)

Each agent machine needs a running node of the database. The node's device must be
delegated by the owner (`sameroot owner delegate` / `sameroot cert add`), so that all
devices write into the owner's subspace and `memory_get` finds the same keys.
