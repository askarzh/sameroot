# Operating Sameroot

How to run nodes, add devices and agents, revoke a key, and move to a successor
database. The commands are those of the `sameroot` tool; each prints its own help
(`sameroot` with no arguments).

## A node and its home

`samerootd` keeps everything in its home, `$SAMEROOT_HOME` (default `~/.sameroot`,
mode 0700):

| File | What it is | Back up? |
|---|---|---|
| `device.key` | This device's signing key | Yes |
| `endpoint.key` | The network identity (iroh endpoint id); relays may allowlist it | Yes |
| `store.redb` | The ledgers | Peers hold copies |
| `blobs/` | Values by hash | Peers hold copies |
| `memory.key` | The agent memory's key (`sameroot-mcp keygen`); the same on all your devices | Yes |
| `peers`, `writecerts`, `agentcerts`, `agents/` | Who to dial, this node's certificates, its agents' keys | Rebuilt by re-joining and delegating |
| `successors`, `late-done`, `delegated` | Succession bookkeeping | No |

The owner key lives outside the node, in `$SAMEROOT_OWNER_HOME` (default
`~/.sameroot-owner`). It creates databases, delegates devices and signs successions.
Keep it on one machine and back it up: it is the identity of your data.

Keys are created with mode 0600 and are never replaced. A key file that can't be
read stops the node instead of being regenerated.

## Running it as a service

On Linux, a systemd user service:

```ini
# ~/.config/systemd/user/sameroot.service
[Unit]
Description=Sameroot node
Wants=network-online.target
After=network-online.target

[Service]
Environment=SAMEROOT_HOME=%h/.sameroot
ExecStart=%h/.local/bin/samerootd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now sameroot
loginctl enable-linger "$USER"     # keep it running without a login session
```

On macOS a LaunchAgent does the same. The node stops cleanly on SIGTERM, so peers see
the connection end at once.

### Relays

Nodes reach each other directly when they can (QUIC with NAT traversal) and through a
relay when they can't.

| `SAMEROOT_RELAY` | What the node does |
|---|---|
| unset | Uses n0's public relays |
| `https://relay.example.org[,…]` | Uses your own relays: [`deploy/relay`](../deploy/relay) runs one behind Caddy, for networks that allow only TCP 443 |
| `none` | Direct connections only |

The node trusts the operating system's certificate store and honours `HTTPS_PROXY` /
`HTTP_PROXY`.

## More devices

On the owner's machine, delegate the other device for a database, then install the
certificate there:

```bash
sameroot owner delegate <db> <device key> --days 365 --name laptop   # prints a certificate
sameroot cert add <certificate hex>                                  # on the laptop
```

The device key is the `device` line of `sameroot status`. A delegated device writes in
the owner's subspace, so every device sees one memory. An undelegated device can
still read and replicate. In a database whose rules allow it, it writes only in its
own subspace.

`sameroot certs` lists the certificates of a database and how long they have left.

## Agents with their own keys

With `SAMEROOT_AGENT=<name>` in the MCP server's environment (`claude`, `codex`,
`agy`…), the node signs that agent's writes with a key of its own:
- the key lives at `agents/<name>.key`;
- the device issues the agent's certificate itself: within the device's own rights, for
  at most 30 days, never past the device's certificate;
- the certificate is renewed in its last week.

One agent can then be revoked without the others. Without `SAMEROOT_AGENT`, writes are
signed by the device.

## Revoking a key

When a device is lost or an agent's key leaks, void its certificate. A void doesn't
delete anything. It makes the certificate's entries stop counting, except for the
ones the void keeps.

```bash
sameroot certs                                   # find the certificate (an id prefix will do)
sameroot void 3f2a91c0 --keep-before 1794580000000
```

Without `--yes` this only prints the plan:
- the entries that will be kept: those this node first saw before `--keep-before`, by
  its own clock, which the thief can't set;
- the entries that will be dropped.

Then:

```bash
sameroot void 3f2a91c0 --keep-before 1794580000000 --yes
```

The void travels to every node like any record, and every node applies it the same
way.

| Option | Meaning |
|---|---|
| `--keep-before now\|MS` | Keep what this node saw before that moment (default: now) |
| `--before MS` | Only entries dated before MS lose their effect; later ones stay valid |
| `--total` | Drop everything under the certificate |
| `--owner` | Sign with the owner key instead of this node's device |

A device can void the certificates it issued, such as its agents'. The owner can void
any certificate in the database.

A void stops a key's writes from counting. It doesn't take back what the key's holder
could read: for that, the data needs a new memory key.

## Succession: starting over without the history

Within one database nothing is ever deleted: every write, delete and revocation stays
a record. To shed the history, the owner moves the database to a successor.

```bash
sameroot owner succeed           # the plan: the cut, what is carried, which devices, the new id
sameroot owner succeed --yes     # publish it
```

1. **The cut.** The owner's node takes its current fingerprint as the cut and computes
   the current state of the owner's subspace.
2. **The successor.** The owner signs that state anew in a new database with the same
   rules. Every device whose certificate the owner's node holds gets a certificate
   there, published under `.grants/` (`sameroot list` leaves those paths out). A
   *forward* record in the old database names the successor.
3. **Nodes follow on their own.** A node that sees the forward:
   - stops writing to the old database;
   - fetches the successor from the same peers and checks it against the forward;
   - installs its certificate from `.grants/`.

   From then on, requests for the old database, an id prefix in `SAMEROOT_DB`
   included, land in the successor. A device that wrote under a certificate and gets
   none in the successor refuses to write, instead of writing where nobody looks.
   Delegate it with `sameroot owner delegate <successor> <device>`.
4. **Late writes.** Writes that reached the old database after the cut are listed by
   `sameroot late`; `sameroot late --resubmit` writes this device's own anew in the
   successor. A key that has a newer entry there is skipped.
5. **Collection.** After a 14-day read-only grace, `sameroot gc <old db>` deletes the old
   records and keeps a stub of about 1 KB: the genesis and the forward. Values no
   database refers to any more leave the blob store. A node that was offline for
   longer still finds the successor: the stub hands it the forward when it connects.
   `--force` skips the grace.

Limits of this first version:
- only the owner's subspace is carried;
- grants go only to the devices that wrote;
- the owner key and the memory key stay the same.

## Environment

| Variable | Used by | Meaning |
|---|---|---|
| `SAMEROOT_HOME` | all | The node's home (default `~/.sameroot`) |
| `SAMEROOT_OWNER_HOME` | `sameroot owner …` | The owner key's home (default `~/.sameroot-owner`) |
| `SAMEROOT_RELAY` | `samerootd` | Relays: unset (n0's), URLs, or `none` |
| `SAMEROOT_BLOB_GC_SECS` | `samerootd` | How often the blob store collects values no put that counts refers to (default 3600; only once a database was retired). Values of voided, negated or expired puts are never fetched |
| `SAMEROOT_DB` | `sameroot-mcp` | The database id or a prefix |
| `SAMEROOT_AGENT` | `sameroot-mcp` | The agent's name, for a key of its own |
| `SAMEROOT_MEMORY_KEY` | `sameroot-mcp` | The memory key file (default `$SAMEROOT_HOME/memory.key`) |
| `SAMEROOT_PLAIN_NAMES`, `SAMEROOT_ALLOW_PLAINTEXT` | `sameroot-mcp` | See [mcp.md](mcp.md) |

The `sameroot` tool takes `--db <id prefix>` when the node holds several databases.
