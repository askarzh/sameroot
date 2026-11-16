//! `sameroot` — the command-line tool (`docs/design/0001-architecture.md` §4).
//!
//! Talks to the local `samerootd` over its socket, and carries the owner tools: the
//! owner key never enters the node (design §6); it lives in `$SAMEROOT_OWNER_HOME`
//! (default `~/.sameroot-owner`) and signs the genesis and device certificates.

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;

use sameroot_core::cbor::{Map, Value};
use sameroot_core::hash::{hex, unhex};
use sameroot_core::ledger::{Kind, Trie};
use sameroot_core::succession::{self, Carried, Cut};
use sameroot_core::{
    Area, Cert, Digest, Genesis, Keep, Op, Path, PublicKey, SecretKey, SignedCert, SignedGenesis,
    Subspace, Void, now_ms,
};
use sameroot_rpc::{Fields, request};

const USAGE: &str = "usage: sameroot <command>

node:
  status                          node, databases, peers, state hashes
  put <path> <value>              write (signed by this node's device key)
  get <path> [--subspace <hex>]   read the current value
  del <path>                      delete (a signed tombstone)
  negate <entry-id>               negate one entry (it stays in the ledger, loses its effect)
  list [prefix] [--all]           list current values in this node's subspace
                                  (--all: every subspace, strangers' included)
  invite                          print an invite to the database
  join <invite>                   replicate a database through a peer
  cert add <hex>                  install a delegation certificate
  late [--resubmit]               this node's writes that reached a succeeded database
                                  after its cut; --resubmit writes them anew in the
                                  successor
  gc <db> [--force]               collect a succeeded database down to its stub
                                  (after its 14-day read-only grace, unless --force)
  certs                           the certificates of the database
  void <cert> [--keep-before now|MS] [--before MS] [--total] [--owner] [--yes]
                                  revoke a certificate (an id prefix will do):
                                  entries this node saw before --keep-before
                                  (default: now) are kept, later ones dropped;
                                  --total drops everything under it. Signed by this
                                  node's device, or by the owner key with --owner.
                                  Without --yes it only shows the plan.
options: --db <id-prefix>  (needed when the node holds several databases)

owner (the owner key stays out of the node):
  owner init                      create the owner key
  owner create-db <name> [--max-value BYTES]
                                  create a database and delegate this node's device
                                  (largest value: 1 MiB unless set)
  owner delegate <db> <device> [--days N] [--name X]
                                  print a certificate for another device
  owner succeed [--days N] [--yes]
                                  succession (rewrite mode): a new database carrying
                                  the owner's state at a cut, with the devices'
                                  grants (renewed for N days with --days, else
                                  keeping their ends); the old one turns read-only.
                                  Without --yes it only shows the plan";

/// The first `n` characters of `s`, or all of it if shorter (ids are hex; "shared"
/// and "?" are shorter than an id prefix).
fn short(s: &str, n: usize) -> &str {
    s.get(..n).unwrap_or(s)
}

fn home() -> PathBuf {
    std::env::var_os("SAMEROOT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".sameroot"))
}

fn owner_home() -> PathBuf {
    std::env::var_os("SAMEROOT_OWNER_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".sameroot-owner")
        })
}

fn rpc(req: Map) -> Result<Map, String> {
    let socket = home().join("samerootd.sock");
    let resp = sameroot_rpc::call(&socket, &req).map_err(|e| {
        format!(
            "no node at {} ({e}) — is samerootd running?",
            socket.display()
        )
    })?;
    match resp.flag("ok") {
        Some(true) => Ok(resp),
        _ => Err(resp.text("error").unwrap_or("request failed").to_owned()),
    }
}

fn owner_key() -> Result<SecretKey, String> {
    let path = owner_home().join("owner.key");
    let bytes = std::fs::read(&path).map_err(|_| {
        format!(
            "no owner key at {} — run `sameroot owner init`",
            path.display()
        )
    })?;
    Ok(SecretKey::from_seed(
        bytes.try_into().map_err(|_| "owner key is not 32 bytes")?,
    ))
}

fn device_cert(
    owner: &SecretKey,
    db: Digest,
    device: PublicKey,
    days: u64,
    name: Option<String>,
) -> SignedCert {
    let now = now_ms();
    Cert {
        issuer: owner.public(),
        subject: device,
        parent: None,
        db,
        area: Area {
            subspace: Subspace::Owner(owner.public()),
            path_prefix: Path::default(),
            ops: vec![Op::Put, Op::Delete, Op::Negate],
        },
        not_before: now.saturating_sub(5 * 60 * 1000),
        not_after: now.saturating_add(days.saturating_mul(24 * 3600 * 1000)),
        name,
        endpoint: None,
    }
    .sign(owner)
}

/// A time on the command line: `now` or milliseconds since the epoch.
fn parse_time(s: &str) -> Result<u64, String> {
    if s == "now" {
        Ok(now_ms())
    } else {
        s.parse()
            .map_err(|_| format!("{s:?}: a time is `now` or milliseconds since the epoch"))
    }
}

/// The one certificate in `certs` whose id starts with `prefix`.
fn find_cert<'a>(certs: &'a [Value], prefix: &str) -> Result<&'a Map, String> {
    let prefix = prefix.to_ascii_lowercase();
    let found: Vec<&Map> = certs
        .iter()
        .filter_map(|c| match c {
            Value::Map(m) if m.text("id").is_some_and(|id| id.starts_with(&prefix)) => Some(m),
            _ => None,
        })
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("no certificate {prefix}… in this database")),
        _ => Err(format!(
            "{prefix}… matches {} certificates; give more of the id",
            found.len()
        )),
    }
}

/// A keep list sent as concatenated 32-byte ids.
fn ids(bytes: &[u8]) -> Vec<Digest> {
    bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| Digest(*c))
        .collect()
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn print_entry(e: &Map) {
    let path = e.text("path").unwrap_or("?");
    let signer = short(e.text("signer").unwrap_or("?"), 8);
    let subspace = e
        .text("subspace")
        .map(|s| &s[..8.min(s.len())])
        .unwrap_or("?");
    if e.flag("deleted") == Some(true) {
        println!(
            "{path}\t(deleted)\tsubspace {subspace} · signer {signer} · ts {}",
            e.uint("ts").unwrap_or(0)
        );
    } else {
        let value = e
            .bytes("value")
            .map(|v| match sameroot_seal::sealed_key_id(v) {
                // Sealed by an application (e.g. the MCP memory): shown, not dumped.
                Some(kid) => format!("[sealed · key {kid} · {} bytes]", v.len()),
                None => String::from_utf8_lossy(v).into_owned(),
            })
            .unwrap_or_default();
        println!(
            "{path}\t{value}\tsubspace {subspace} · signer {signer} · ts {}",
            e.uint("ts").unwrap_or(0)
        );
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut args = args;
    let db = match args.iter().position(|a| a == "--db") {
        Some(i) if i + 1 < args.len() => {
            let v = args.remove(i + 1);
            args.remove(i);
            Some(v)
        }
        _ => None,
    };
    let with_db = |mut m: Map| {
        if let Some(d) = &db {
            m.insert("db", Value::Text(d.clone()));
        }
        m
    };
    let flag = |args: &mut Vec<String>, name: &str| -> Option<String> {
        let i = args.iter().position(|a| a == name)?;
        if i + 1 >= args.len() {
            return None;
        }
        let v = args.remove(i + 1);
        args.remove(i);
        Some(v)
    };
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["status"] => {
            let r = rpc(request("status"))?;
            println!("device    {}", r.text("device").unwrap_or("?"));
            println!("endpoint  {}", r.text("endpoint").unwrap_or("?"));
            let relays: Vec<_> = r
                .list("relay")
                .unwrap_or(&[])
                .iter()
                .filter_map(|v| {
                    if let Value::Text(t) = v {
                        Some(t.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            println!(
                "relay     {}",
                if relays.is_empty() {
                    "-".to_owned()
                } else {
                    relays.join(", ")
                }
            );
            for d in r.list("databases").unwrap_or(&[]) {
                let Value::Map(d) = d else { continue };
                let peers = d.list("peers").map_or(0, <[Value]>::len);
                let missing = d.uint("valuesMissing").unwrap_or(0);
                println!(
                    "database  {} \"{}\" · {} records · state {} · {} peer session(s) · writes as {}{}{}",
                    short(d.text("id").unwrap_or("?"), 16),
                    d.text("name").unwrap_or(""),
                    d.uint("records").unwrap_or(0),
                    short(d.text("state").unwrap_or("?"), 16),
                    peers,
                    short(d.text("writesAs").unwrap_or("?"), 8),
                    if d.flag("delegated") == Some(true) {
                        " (delegated)"
                    } else {
                        ""
                    },
                    if missing > 0 {
                        format!(" · {missing} value(s) still arriving")
                    } else {
                        String::new()
                    }
                );
                if d.uint("retired").is_some() {
                    println!("          retired: only its stub is kept");
                } else if let Some(next) = d.text("successor") {
                    println!(
                        "          succeeded by {}{} · read-only{}",
                        short(next, 16),
                        if d.flag("followed") == Some(true) {
                            ", followed"
                        } else {
                            " (not here yet)"
                        },
                        match d.uint("late") {
                            Some(n) if n > 0 => format!(" · {n} late write(s): `sameroot late`"),
                            _ => String::new(),
                        }
                    );
                }
            }
        }
        ["put", path, value] => {
            let mut m = with_db(request("put"));
            m.insert("path", Value::Text((*path).into()))
                .insert("value", Value::Bytes(value.as_bytes().to_vec()));
            let r = rpc(m)?;
            if let Some(Value::Map(e)) = r.get("entry") {
                println!(
                    "ok {} ts {}",
                    short(e.text("id").unwrap_or("?"), 16),
                    e.uint("ts").unwrap_or(0)
                );
            }
        }
        ["get", path, rest @ ..] => {
            let mut m = with_db(request("get"));
            m.insert("path", Value::Text((*path).into()));
            if let ["--subspace", s] = rest {
                m.insert("subspace", Value::Text((*s).into()));
            }
            match rpc(m)?.get("entry") {
                Some(Value::Map(e)) => print_entry(e),
                _ => println!("(not found)"),
            }
        }
        ["negate", target] => {
            let mut m = with_db(request("negate"));
            m.insert("target", Value::Text((*target).into()));
            let r = rpc(m)?;
            if let Some(Value::Map(e)) = r.get("entry") {
                println!("negated by {}", short(e.text("id").unwrap_or("?"), 16));
            }
        }
        ["del", path] => {
            let mut m = with_db(request("del"));
            m.insert("path", Value::Text((*path).into()));
            rpc(m)?;
            println!("deleted");
        }
        ["list", rest @ ..] => {
            let mut m = with_db(request("list"));
            if rest.contains(&"--all") {
                m.insert("all", Value::Bool(true));
            }
            if let Some(prefix) = rest.iter().find(|a| **a != "--all") {
                m.insert("prefix", Value::Text((*prefix).into()));
            }
            // A page at a time.
            let mut offset = 0;
            loop {
                let mut page = m.clone();
                page.insert("offset", Value::Uint(offset));
                let r = rpc(page)?;
                for e in r.list("entries").unwrap_or(&[]) {
                    if let Value::Map(e) = e {
                        print_entry(e);
                    }
                }
                match r.uint("next") {
                    Some(n) if n > offset => offset = n,
                    _ => break,
                }
            }
        }
        ["invite"] => println!(
            "{}",
            rpc(with_db(request("invite")))?
                .text("invite")
                .unwrap_or("")
        ),
        ["join", invite] => {
            let mut m = request("join");
            m.insert("invite", Value::Text((*invite).into()));
            let r = rpc(m)?;
            println!(
                "joining {} — check `sameroot status`",
                short(r.text("db").unwrap_or("?"), 16)
            );
        }
        ["cert", "add", cert] => {
            let mut m = request("cert.add");
            m.insert(
                "cert",
                Value::Bytes(unhex(cert.trim()).ok_or("certificate must be hex")?),
            );
            let r = rpc(m)?;
            println!(
                "installed for {}{}",
                short(r.text("db").unwrap_or("?"), 16),
                if r.flag("forThisNode") == Some(true) {
                    " — this node now writes under it"
                } else {
                    ""
                }
            );
        }
        ["certs"] => {
            let r = rpc(with_db(request("certs")))?;
            let now = now_ms();
            for c in r.list("certs").unwrap_or(&[]) {
                let Value::Map(c) = c else { continue };
                let not_after = c.uint("notAfter").unwrap_or(0);
                println!(
                    "{}  {}  subject {} · issuer {}{} · {}",
                    short(c.text("id").unwrap_or("?"), 16),
                    c.text("name").unwrap_or("-"),
                    short(c.text("subject").unwrap_or("?"), 8),
                    short(c.text("issuer").unwrap_or("?"), 8),
                    c.text("parent")
                        .map(|p| format!(" · under {}", short(p, 8)))
                        .unwrap_or_default(),
                    if not_after <= now {
                        "expired".to_owned()
                    } else {
                        format!("{} days left", (not_after - now) / (24 * 3600 * 1000))
                    }
                );
            }
        }
        ["void", cert, ..] => {
            let cert = cert.to_string();
            let keep_before = flag(&mut args, "--keep-before")
                .map(|t| parse_time(&t))
                .transpose()?
                .unwrap_or_else(now_ms);
            let before = flag(&mut args, "--before")
                .map(|t| parse_time(&t))
                .transpose()?;
            let total = args.iter().any(|a| a == "--total");
            let as_owner = args.iter().any(|a| a == "--owner");
            let yes = args.iter().any(|a| a == "--yes");
            if total && before.is_some() {
                return Err("--total drops everything; --before can't apply".into());
            }
            let certs = rpc(with_db(request("certs")))?;
            let c = find_cert(certs.list("certs").unwrap_or(&[]), &cert)?;
            let id = c.text("id").ok_or("certificate without id")?.to_owned();
            let mut m = with_db(request("void.plan"));
            m.insert("cert", Value::Text(id.clone()))
                .insert("keepBefore", Value::Uint(keep_before));
            let plan = rpc(m)?;
            let keep = if total {
                Vec::new()
            } else {
                ids(plan.bytes("keep").unwrap_or(&[]))
            };
            let dropped = plan.list("dropped").unwrap_or(&[]);
            println!(
                "void of {} ({}), signed by {}",
                short(&id, 16),
                c.text("name").unwrap_or("-"),
                if as_owner { "the owner" } else { "this node" }
            );
            if total {
                println!(
                    "total: every entry under it loses its effect ({} entries)",
                    ids(plan.bytes("keep").unwrap_or(&[])).len() + dropped.len()
                );
            } else {
                println!("keep {} entries seen before {keep_before}", keep.len());
                println!("drop {} entries:", dropped.len());
                for d in dropped.iter().take(20) {
                    let Value::Map(d) = d else { continue };
                    println!(
                        "  {}  {}  ts {}",
                        short(d.text("id").unwrap_or("?"), 16),
                        d.text("path").unwrap_or("?"),
                        d.uint("ts").unwrap_or(0)
                    );
                }
                if dropped.len() > 20 {
                    println!("  … and {} more", dropped.len() - 20);
                }
                if let Some(b) = before {
                    println!("entries dated from {b} on stay valid");
                }
            }
            if !yes {
                println!("(plan only: add --yes to sign and send it)");
                return Ok(());
            }
            let r = if as_owner {
                let owner = owner_key()?;
                let db = Digest::from_hex(plan.text("db").ok_or("plan without db")?)
                    .ok_or("bad db id")?;
                let target = Digest::from_hex(&id).ok_or("bad cert id")?;
                let mut void = Void::of_cert(db, target, owner.public());
                if !total {
                    void.keep = Some(Keep {
                        root: Trie::build(keep.iter().map(|d| (Kind::Entry, *d))).root(),
                        count: keep.len() as u64,
                    });
                    void.before = before;
                }
                let mut m = request("void.add");
                m.insert("void", Value::Bytes(void.sign(&owner).encode()));
                if !total {
                    m.insert(
                        "keep",
                        Value::Bytes(keep.iter().flat_map(|d| d.0).collect()),
                    );
                }
                rpc(m)?
            } else {
                let mut m = with_db(request("void.sign"));
                m.insert("cert", Value::Text(id))
                    .insert("keepBefore", Value::Uint(keep_before))
                    .insert("total", Value::Bool(total));
                if let Some(b) = before {
                    m.insert("before", Value::Uint(b));
                }
                rpc(m)?
            };
            println!("void {} sent", short(r.text("id").unwrap_or("?"), 16));
        }
        ["late", rest @ ..] => {
            if rest.contains(&"--resubmit") {
                let r = rpc(with_db(request("late.resubmit")))?;
                println!(
                    "{} written anew in the successor, {} skipped (newer there, or a negation)",
                    r.uint("written").unwrap_or(0),
                    r.uint("skipped").unwrap_or(0)
                );
                return Ok(());
            }
            let r = rpc(with_db(request("late")))?;
            let entries = r.list("entries").unwrap_or(&[]);
            println!(
                "{} late entr{} in {}",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" },
                short(r.text("db").unwrap_or("?"), 16)
            );
            for e in entries {
                let Value::Map(e) = e else { continue };
                println!(
                    "  {}  {} {}  ts {}{}{}",
                    short(e.text("id").unwrap_or("?"), 16),
                    e.text("op").unwrap_or("?"),
                    e.text("path").unwrap_or("?"),
                    e.uint("ts").unwrap_or(0),
                    match (e.flag("own"), e.text("agent")) {
                        (Some(true), Some(a)) => format!(" · mine (agent {a})"),
                        (Some(true), None) => " · mine".to_owned(),
                        _ => String::new(),
                    },
                    if e.flag("done") == Some(true) {
                        " · done"
                    } else {
                        ""
                    }
                );
            }
        }
        ["gc", db, rest @ ..] => {
            let mut m = request("gc");
            m.insert("db", Value::Text((*db).into()));
            if rest.contains(&"--force") {
                m.insert("force", Value::Bool(true));
            }
            let r = rpc(m)?;
            println!(
                "collected: {} records deleted; the stub points to {}",
                r.uint("removed").unwrap_or(0),
                short(r.text("successor").unwrap_or("?"), 16)
            );
        }
        ["owner", "succeed", rest @ ..] => {
            let yes = rest.contains(&"--yes");
            let renew_until = flag(&mut args, "--days")
                .map(|d| d.parse::<u64>())
                .transpose()
                .map_err(|_| "--days must be a number")?
                .map(|d| now_ms().saturating_add(d.saturating_mul(24 * 3600 * 1000)));
            let owner = owner_key()?;
            let cut = rpc(with_db(request("succession.cut")))?;
            let parent = SignedGenesis::decode(cut.bytes("genesis").ok_or("no genesis")?)
                .map_err(|e| e.to_string())?;
            let digest = |b: Option<&[u8]>| -> Result<Digest, String> {
                Ok(Digest(
                    b.ok_or("missing digest")?
                        .try_into()
                        .map_err(|_| "bad digest")?,
                ))
            };
            let state: Vec<Carried> = cut
                .list("state")
                .unwrap_or(&[])
                .iter()
                .map(|v| {
                    let Value::Map(m) = v else {
                        return Err("bad state".to_owned());
                    };
                    let path = Path(
                        m.list("path")
                            .ok_or("no path")?
                            .iter()
                            .map(|c| match c {
                                Value::Bytes(b) => Ok(b.clone()),
                                _ => Err("bad path".to_owned()),
                            })
                            .collect::<Result<_, _>>()?,
                    );
                    Ok(Carried {
                        path,
                        value_hash: digest(m.bytes("hash"))?,
                        value_size: m.uint("size").ok_or("no size")?,
                        exp: m.uint("exp"),
                    })
                })
                .collect::<Result<_, _>>()?;
            let devices: Vec<SignedCert> = cut
                .list("devices")
                .unwrap_or(&[])
                .iter()
                .filter_map(|v| match v {
                    Value::Bytes(b) => SignedCert::decode(b).ok(),
                    _ => None,
                })
                .collect();
            let plan = succession::rewrite_renewing(
                &parent,
                &owner,
                &Cut {
                    root: digest(cut.bytes("cutRoot"))?,
                    count: cut.uint("cutCount").unwrap_or(0),
                    as_of: cut.uint("asOf").unwrap_or(0),
                },
                &state,
                &devices,
                None,
                now_ms(),
                renew_until,
            )
            .map_err(|e| e.to_string())?;
            let child = plan.genesis.id();
            println!(
                "succession of {} \"{}\"",
                short(&parent.id().to_hex(), 16),
                parent.genesis.name
            );
            println!(
                "cut: {} records, ledger root {}",
                cut.uint("cutCount").unwrap_or(0),
                short(&hex(cut.bytes("cutRoot").unwrap_or(&[])), 16)
            );
            println!(
                "carry {} value(s) of the owner's subspace, signed anew by the owner",
                plan.entries.len() - plan.certs.len()
            );
            match cut.uint("otherKeys").unwrap_or(0) {
                0 => {}
                n => println!(
                    "not carried: {n} key(s) in other subspaces (rewrite carries only the owner's)"
                ),
            }
            println!("devices carried over ({}):", plan.certs.len());
            let now = now_ms();
            for c in &plan.certs {
                println!(
                    "  {} {} · {} days",
                    short(&c.cert.subject.to_hex(), 8),
                    c.cert.name.as_deref().unwrap_or("-"),
                    c.cert.not_after.saturating_sub(now) / (24 * 3600 * 1000)
                );
            }
            println!("successor {}", child.to_hex());
            if !yes {
                println!("(plan only: add --yes to publish it)");
                return Ok(());
            }
            let status = rpc(request("status"))?;
            let device = status.text("device").unwrap_or("");
            let mut m = request("db.add");
            m.insert("genesis", Value::Bytes(plan.genesis.encode()));
            if let Some(c) = plan
                .certs
                .iter()
                .find(|c| c.cert.subject.to_hex() == device)
            {
                m.insert("cert", Value::Bytes(c.encode()));
            }
            rpc(m)?;
            // The grants first, in the same call as their values, so the values are
            // never left without the entries that keep them; the forward last, so no
            // node follows a successor still being filled.
            let (state, grants) = plan.entries.split_at(plan.entries.len() - plan.certs.len());
            if !grants.is_empty() {
                let mut m = request("entries.add");
                m.insert(
                    "entries",
                    Value::Array(grants.iter().map(|e| Value::Bytes(e.encode())).collect()),
                )
                .insert(
                    "values",
                    Value::Array(plan.values.iter().cloned().map(Value::Bytes).collect()),
                );
                rpc(m)?;
            }
            for chunk in state.chunks(500) {
                let mut m = request("entries.add");
                m.insert(
                    "entries",
                    Value::Array(chunk.iter().map(|e| Value::Bytes(e.encode())).collect()),
                );
                rpc(m)?;
            }
            let mut m = request("forward.add");
            m.insert("forward", Value::Bytes(plan.forward.encode()));
            rpc(m)?;
            println!(
                "published: {} follows {}; nodes follow on their own, and the old database \
                 takes no more writes.\nAfter the grace period: sameroot gc {}",
                short(&child.to_hex(), 16),
                short(&parent.id().to_hex(), 16),
                parent.id().to_hex()
            );
        }
        ["owner", "init"] => {
            let dir = owner_home();
            let path = dir.join("owner.key");
            if path.exists() {
                return Err(format!("{} already exists", path.display()));
            }
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            let key = SecretKey::generate();
            // Owner-only from the start, never over an existing key, synced.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            std::io::Write::write_all(&mut f, &key.seed()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            println!(
                "owner {}\nkey in {} — back it up; it is the identity of your data",
                key.public().to_hex(),
                path.display()
            );
        }
        ["owner", "create-db", name, ..] => {
            let name = name.to_string();
            let max_value = flag(&mut args, "--max-value")
                .map(|d| d.parse::<u64>())
                .transpose()
                .map_err(|_| "--max-value must be a number of bytes")?;
            let owner = owner_key()?;
            let status = rpc(request("status"))?;
            let device = PublicKey::from_hex(
                status
                    .text("device")
                    .ok_or("node did not report its device key")?,
            )
            .ok_or("bad device key")?;
            let mut genesis = Genesis::new(
                &name,
                owner.public(),
                sameroot_core::logic::presets::own_subspace(),
                now_ms(),
            );
            if let Some(m) = max_value {
                genesis.limits.max_value = m;
            }
            let genesis = genesis.sign(&owner);
            let db = genesis.id();
            let cert = device_cert(&owner, db, device, 365, hostname());
            let mut m = request("db.add");
            m.insert("genesis", Value::Bytes(genesis.encode()))
                .insert("cert", Value::Bytes(cert.encode()));
            rpc(m)?;
            println!(
                "database {}\nowner {}\nthis node ({}) writes in the owner's subspace",
                db.to_hex(),
                owner.public().to_hex(),
                &device.to_hex()[..8]
            );
        }
        ["owner", "delegate", db, device, ..] => {
            let (db, device) = (db.to_string(), device.to_string());
            let days = flag(&mut args, "--days")
                .map(|d| d.parse::<u64>())
                .transpose()
                .map_err(|_| "--days must be a number")?
                .unwrap_or(365);
            let name = flag(&mut args, "--name");
            let owner = owner_key()?;
            let db = Digest(
                unhex(&db)
                    .ok_or("database id must be hex")?
                    .try_into()
                    .map_err(|_| "database id must be 32 bytes")?,
            );
            let device =
                PublicKey::from_hex(&device).ok_or("device key must be 64 hex characters")?;
            println!(
                "{}",
                hex(&device_cert(&owner, db, device, days, name).encode())
            );
        }
        _ => return Err(USAGE.to_owned()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_never_panics() {
        assert_eq!(short("shared", 8), "shared");
        assert_eq!(short("?", 16), "?");
        assert_eq!(short("0123456789abcdef0123", 16), "0123456789abcdef");
        assert_eq!(short("", 4), "");
    }

    #[test]
    fn times_and_certificate_prefixes() {
        assert_eq!(parse_time("1700000000000"), Ok(1_700_000_000_000));
        assert!(parse_time("now").unwrap() > 1_700_000_000_000);
        assert!(parse_time("yesterday").is_err());

        let cert = |id: &str| {
            let mut m = Map::new();
            m.insert("id", Value::Text(id.into()));
            Value::Map(m)
        };
        let certs = [cert("abc123"), cert("abd456"), cert("ff0000")];
        assert_eq!(find_cert(&certs, "ABC").unwrap().text("id"), Some("abc123"));
        assert!(find_cert(&certs, "ab").unwrap_err().contains("matches 2"));
        assert!(find_cert(&certs, "00").is_err());

        let a = Digest([1; 32]);
        let b = Digest([2; 32]);
        let bytes: Vec<u8> = [a.0, b.0].concat();
        assert_eq!(ids(&bytes), vec![a, b]);
        assert!(ids(&bytes[..40]).len() == 1, "a partial id is dropped");
    }

    #[test]
    fn device_certificates_last_and_cover_the_owner() {
        let owner = SecretKey::from_seed([1; 32]);
        let device = SecretKey::from_seed([2; 32]).public();
        let c = device_cert(&owner, Digest([3; 32]), device, u64::MAX, None);
        assert_eq!(
            c.cert.not_after,
            u64::MAX,
            "saturates instead of overflowing"
        );
        assert_eq!(c.cert.subject, device);
        assert_eq!(c.cert.area.subspace, Subspace::Owner(owner.public()));
        // The certificate a delegation prints decodes back.
        assert_eq!(SignedCert::decode(&c.encode()).unwrap(), c);
    }
}
