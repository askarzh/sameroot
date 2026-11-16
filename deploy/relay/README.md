# Running your own relay

Nodes reach each other directly when they can, and through an iroh relay when they
can't, e.g. on networks that allow only TCP 443. n0's public relays are the default;
this directory runs your own, behind any TLS-terminating reverse proxy.

- **Relay:** `compose.yaml` runs `iroh-relay` 1.4.1 (built on the host) with
  `relay.toml`, listening on port 3340 inside its network (no ports published).
- **TLS:** point your proxy at `https://relay.example.org` →
  `sameroot-relay-relay-1:3340`.
- **Access:** `relay.toml` can restrict the relay to your nodes' endpoint ids (the
  `endpoint` line of `sameroot status`).
- **Nodes:** `SAMEROOT_RELAY=https://relay.example.org samerootd`.

Check: `curl https://relay.example.org/ping` → `200`.
