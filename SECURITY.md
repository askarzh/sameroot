# Security

Sameroot is an experimental prototype, maintained by one person, without an
independent security review. Its formats and protocol may still change. See
[docs/threat-model.md](docs/threat-model.md) for what it protects and what it doesn't.

## Reporting a vulnerability

Please don't open a public issue. Report it privately through GitHub's **Report a
vulnerability** button on this repository (private vulnerability reporting).

Say what you found, how to reproduce it, and what an attacker gains. You'll get an
answer as soon as possible, but there is no response-time guarantee. Fixes land on
`main`; there are no maintained release branches yet.

## Scope

In scope: anything that breaks what the threat model says is protected. For example:
- forging or slipping in a record the rules don't allow;
- reading a sealed value without the key;
- making nodes disagree on the state of the same records;
- crashing or exhausting a node from the network beyond its documented limits.

Out of scope: what the threat model lists as not protected, such as metadata, the
openness of a database to whoever knows its id, and availability.
