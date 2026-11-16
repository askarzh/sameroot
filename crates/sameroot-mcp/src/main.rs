//! `sameroot-mcp`: shared memory for AI agents, an MCP server over the local node.
//!
//! It speaks MCP over stdio (JSON-RPC 2.0, one message per line) and talks to the
//! node (`samerootd`) over its Unix socket. Every agent on every machine that runs
//! a node of the same database sees the same memory: a write here is a signed
//! ledger record, pushed to the other nodes at once.
//!
//! The ledger is readable by every node, so the application protects what it stores
//! (`sameroot-seal`): values are sealed, and key names are hidden: a name such as
//! `notes/topic` is stored as `~/<token>/<token>`, with the real name inside the
//! sealed value. Signed headers (who wrote, when, sizes) stay public.
//!
//! Environment:
//! - `SAMEROOT_HOME`: the node's home (default `~/.sameroot`); its socket is
//!   `samerootd.sock` there.
//! - `SAMEROOT_DB`: the database (id or prefix); required when the node holds more
//!   than one.
//! - `SAMEROOT_MEMORY_KEY`: the memory key file (default `$SAMEROOT_HOME/memory.key`),
//!   32 random bytes shared by the owner's devices. Create one with
//!   `sameroot-mcp keygen`.
//! - `SAMEROOT_AGENT`: this agent's name (e.g. `claude`, `codex`, `agy`); the node
//!   signs its writes with a key of its own, certified by the device.
//! - `SAMEROOT_PLAIN_NAMES=1`: store key names as they are (values are still sealed).
//! - `SAMEROOT_ALLOW_PLAINTEXT=1`: write unsealed values when there is no key.

use std::cell::RefCell;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use sameroot_core::cbor::{Map, Value};
use sameroot_rpc::{Fields, request};
use sameroot_seal::{MemoryKey, is_hidden_path, is_sealed, sealed_key_id};
use serde_json::{Value as Json, json};

const PROTOCOL_VERSION: &str = "2025-06-18";
const INSTRUCTIONS: &str = "Shared memory across this user's agents and machines, backed by a Sameroot \
node. Keys are paths like `notes/topic` or `tasks/42`; values are JSON. memory_set writes (it reaches \
the user's other machines within about a second), memory_get reads one key, memory_list lists a \
prefix, memory_delete deletes, memory_provenance tells who wrote a key and when. Values and key names \
are encrypted with the user's memory key (memory_status shows it); the depth of a key, who wrote it \
and when stay visible to the nodes. Still don't store credentials.";

/// The marker of the envelope that carries the real name inside a sealed value.
const ENVELOPE: &str = "$sameroot";

/// Keys per `memory_list` page by default, and at most.
const LIST_PAGE: u64 = 100;
const LIST_MAX: u64 = 1000;

/// A call to the node: request in, response (with `ok: true`) or error out.
type Rpc<'a> = &'a dyn Fn(Map) -> Result<Map, String>;

/// What the tools need besides the node: the memory key and the database id.
struct Ctx {
    key: Option<MemoryKey>,
    hide_names: bool,
    allow_plaintext: bool,
    db_prefix: String,
    db: RefCell<Option<[u8; 32]>>,
}

/// A value as read back: the name it was stored under, the value, and how it was
/// protected.
struct Opened {
    name: Option<String>,
    value: Json,
    sealed: bool,
}

fn home() -> PathBuf {
    std::env::var_os("SAMEROOT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".sameroot")
        })
}

fn key_path() -> PathBuf {
    std::env::var_os("SAMEROOT_MEMORY_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join("memory.key"))
}

fn node_rpc(req: Map) -> Result<Map, String> {
    let socket = home().join("samerootd.sock");
    let mut req = req;
    if let Ok(db) = std::env::var("SAMEROOT_DB")
        && !db.is_empty()
    {
        req.insert("db", Value::Text(db));
    }
    // Writes are signed by this agent's own key (design 0004 §3), so one agent can be
    // revoked without the others.
    if let Ok(agent) = std::env::var("SAMEROOT_AGENT")
        && !agent.is_empty()
    {
        req.insert("agent", Value::Text(agent));
    }
    let resp = sameroot_rpc::call(&socket, &req).map_err(|e| {
        format!(
            "no Sameroot node at {} ({e}); is samerootd running?",
            socket.display()
        )
    })?;
    match resp.flag("ok") {
        Some(true) => Ok(resp),
        _ => Err(resp.text("error").unwrap_or("request failed").to_owned()),
    }
}

fn decode_plain(bytes: &[u8]) -> Json {
    match std::str::from_utf8(bytes) {
        Ok(s) => serde_json::from_str(s).unwrap_or_else(|_| Json::String(s.to_owned())),
        Err(_) => json!({ "binary": sameroot_core::hash::hex(bytes) }),
    }
}

impl Ctx {
    /// The full id of the selected database (sealed values are bound to it).
    /// The id values are sealed for: the origin of the database's succession chain
    /// (the node derives it), so a value carried into a successor opens there too and
    /// every client of the chain seals alike, whichever member `SAMEROOT_DB` names.
    fn db(&self, rpc: Rpc) -> Result<[u8; 32], String> {
        if let Some(d) = *self.db.borrow() {
            return Ok(d);
        }
        let r = rpc(request("status"))?;
        let dbs: Vec<&Map> = r
            .list("databases")
            .unwrap_or(&[])
            .iter()
            .filter_map(|d| match d {
                Value::Map(m) => Some(m),
                _ => None,
            })
            .filter(|m| {
                m.text("id")
                    .is_some_and(|id| id.starts_with(&self.db_prefix))
            })
            // Without SAMEROOT_DB, a database already succeeded by another isn't a
            // candidate of its own: requests go to its successor.
            .filter(|m| !self.db_prefix.is_empty() || m.flag("followed") != Some(true))
            .collect();
        let [m] = dbs.as_slice() else {
            return Err("can't tell which database this memory is: set SAMEROOT_DB".into());
        };
        let id = match (m.text("origin"), m.text("id")) {
            (Some(o), _) => o,
            // A node that predates origins: the database's own id.
            (None, Some(id)) if m.get("successor").is_none() && m.get("followed").is_none() => id,
            _ => {
                return Err(
                    "the node doesn't hold the first database of this one's succession chain, \
                     so values can't be sealed for it: join the predecessor too"
                        .into(),
                );
            }
        };
        let bytes: Vec<u8> = (0..id.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(id.get(i..i + 2)?, 16).ok())
            .collect();
        let d: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "bad database id from the node".to_owned())?;
        *self.db.borrow_mut() = Some(d);
        Ok(d)
    }

    /// The key that hides names, if names are hidden.
    fn hider(&self) -> Option<&MemoryKey> {
        self.key.as_ref().filter(|_| self.hide_names)
    }

    /// Where a name is stored: its hidden path, or the name itself.
    fn stored_path(&self, name: &str) -> String {
        match self.hider() {
            Some(k) => k.hide_path(name),
            None => name.to_owned(),
        }
    }

    /// The bytes to store for `value` under `name` (at `path`): sealed, with the
    /// real name inside when names are hidden.
    fn seal(
        &self,
        path: &str,
        name: &str,
        value: &Json,
        rpc: Rpc,
    ) -> Result<(Vec<u8>, bool), String> {
        let body = if self.hider().is_some() {
            json!({ ENVELOPE: 1, "key": name, "value": value })
        } else {
            value.clone()
        };
        let plain = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        match &self.key {
            Some(k) => Ok((k.seal(&self.db(rpc)?, path, &plain), true)),
            None if self.allow_plaintext => Ok((plain, false)),
            None => Err(format!(
                "no memory key at {}: values are encrypted before they enter the shared ledger. \
                 Create one with `sameroot-mcp keygen` (or copy the owner's key there), or set \
                 SAMEROOT_ALLOW_PLAINTEXT=1",
                key_path().display()
            )),
        }
    }

    /// Reads stored bytes found at `path`.
    fn open(&self, path: &str, bytes: &[u8], rpc: Rpc) -> Opened {
        if !is_sealed(bytes) {
            return Opened {
                name: None,
                value: decode_plain(bytes),
                sealed: false,
            };
        }
        let Some(k) = &self.key else {
            return Opened {
                name: None,
                value: json!({ "sealed": true, "readable": false, "reason": "no memory key on this machine" }),
                sealed: true,
            };
        };
        match self
            .db(rpc)
            .and_then(|db| k.open(&db, path, bytes).map_err(|e| e.to_string()))
        {
            Ok(plain) => {
                let body = decode_plain(&plain);
                if body.get(ENVELOPE) == Some(&json!(1)) {
                    Opened {
                        name: body["key"].as_str().map(str::to_owned),
                        value: body["value"].clone(),
                        sealed: true,
                    }
                } else {
                    Opened {
                        name: None,
                        value: body,
                        sealed: true,
                    }
                }
            }
            Err(e) => Opened {
                name: None,
                value: json!({ "sealed": true, "readable": false, "reason": e,
                               "keyId": sealed_key_id(bytes).unwrap_or_default() }),
                sealed: true,
            },
        }
    }

    /// The node's entry for `name`: under its hidden path first, then under the plain
    /// name (written before names were hidden). Deleted entries count only if
    /// `deleted_ok`.
    fn find(&self, name: &str, deleted_ok: bool, rpc: Rpc) -> Result<Option<Map>, String> {
        let mut paths = vec![self.stored_path(name)];
        if paths[0] != name {
            paths.push(name.to_owned());
        }
        for path in paths {
            let mut m = request("get");
            m.insert("path", Value::Text(path));
            // The first path that has an entry decides, deleted or not: a name deleted
            // under its hidden path must not come back from an older plain one.
            if let Some(Value::Map(e)) = rpc(m)?.get("entry") {
                let deleted = e.flag("deleted").unwrap_or(false);
                return Ok((deleted_ok || !deleted).then(|| e.clone()));
            }
        }
        Ok(None)
    }

    /// The JSON for an entry. `name` is the name asked for, when known.
    fn entry_json(&self, e: &Map, name: Option<&str>, with_value: bool, rpc: Rpc) -> Json {
        let path = e.text("path").unwrap_or("");
        let mut j = json!({
            "ts": e.uint("ts").unwrap_or(0),
            "signer": e.text("signer").unwrap_or(""),
            "subspace": e.text("subspace").unwrap_or(""),
            "id": e.text("id").unwrap_or(""),
            "deleted": e.flag("deleted").unwrap_or(false),
            "nameHidden": is_hidden_path(path),
        });
        let mut shown = name.map(str::to_owned);
        if let Some(v) = e.bytes("value") {
            let o = self.open(path, v, rpc);
            if shown.is_none() {
                shown = o.name.clone();
            }
            if with_value {
                j["value"] = o.value;
                j["encrypted"] = json!(o.sealed);
            }
        }
        j["key"] = json!(shown.unwrap_or_else(|| path.to_owned()));
        j
    }
}

fn tools() -> Json {
    let key = json!({ "type": "string", "description": "A path such as notes/topic (components separated by /)" });
    json!([
        { "name": "memory_status",
          "description": "The node and database behind this memory: device, database, record count, root, connected peers, encryption.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "memory_set",
          "description": "Store a JSON value under a key (encrypted, name hidden; replaces the current value; history is kept in the ledger).",
          "inputSchema": { "type": "object", "properties": { "key": key, "value": { "description": "Any JSON value" } },
                           "required": ["key", "value"] } },
        { "name": "memory_get",
          "description": "Read the current value of a key.",
          "inputSchema": { "type": "object", "properties": { "key": key }, "required": ["key"] } },
        { "name": "memory_list",
          "description": "List keys under a prefix (whole components, e.g. notes/), or all keys if empty, in key order: at most `limit` (default 100) per call. To continue, pass the `next` of the answer as `after`. With keys_only, values are left out (cheaper: list first, then memory_get what matters).",
          "inputSchema": { "type": "object", "properties": {
            "prefix": { "type": "string" },
            "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
            "after": { "type": "string", "description": "the `next` of the previous page" },
            "keys_only": { "type": "boolean" } } } },
        { "name": "memory_delete",
          "description": "Delete a key (a signed tombstone; the ledger keeps the record).",
          "inputSchema": { "type": "object", "properties": { "key": key }, "required": ["key"] } },
        { "name": "memory_provenance",
          "description": "Who wrote the current value of a key, when, and its record id.",
          "inputSchema": { "type": "object", "properties": { "key": key }, "required": ["key"] } },
    ])
}

fn arg<'a>(args: &'a Json, k: &str) -> Result<&'a str, String> {
    args.get(k)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("`{k}` is required"))
}

fn list_at(prefix: Option<&str>, rpc: Rpc) -> Result<Vec<Map>, String> {
    let mut out = Vec::new();
    let mut offset = 0;
    loop {
        let mut m = request("list");
        if let Some(p) = prefix {
            m.insert("prefix", Value::Text(p.into()));
        }
        m.insert("offset", Value::Uint(offset));
        let page = rpc(m)?;
        out.extend(
            page.list("entries")
                .unwrap_or(&[])
                .iter()
                .filter_map(|e| match e {
                    Value::Map(e) if !e.flag("deleted").unwrap_or(false) => Some(e.clone()),
                    _ => None,
                }),
        );
        match page.uint("next") {
            Some(n) if n > offset => offset = n,
            _ => return Ok(out),
        }
    }
}

/// Runs one tool; the result is the JSON shown to the agent.
fn call_tool(name: &str, args: &Json, ctx: &Ctx, rpc: Rpc) -> Result<Json, String> {
    match name {
        "memory_status" => {
            let r = rpc(request("status"))?;
            let dbs: Vec<Json> = r
                .list("databases")
                .unwrap_or(&[])
                .iter()
                .filter_map(|d| match d {
                    Value::Map(m) => Some(json!({
                        "id": m.text("id").unwrap_or(""),
                        "name": m.text("name").unwrap_or(""),
                        "records": m.uint("records").unwrap_or(0),
                        "root": m.text("state").unwrap_or(""),
                        "peers": m.list("peers").map_or(0, <[Value]>::len),
                        "writesAs": m.text("writesAs").unwrap_or(""),
                    })),
                    _ => None,
                })
                .collect();
            Ok(
                json!({ "device": r.text("device").unwrap_or(""), "databases": dbs,
                       "selected": ctx.db_prefix,
                       "encryption": match &ctx.key {
                           Some(k) => json!({ "values": "sealed (XChaCha20-Poly1305)",
                                              "names": if ctx.hide_names { "hidden" } else { "public" },
                                              "keyId": k.id_hex() }),
                           None => json!({ "values": if ctx.allow_plaintext { "plaintext (allowed)" } else { "no key: writes refused" },
                                           "names": "public" }),
                       } }),
            )
        }
        "memory_set" => {
            let key = arg(args, "key")?;
            let value = args.get("value").ok_or("`value` is required")?;
            let path = ctx.stored_path(key);
            let (bytes, sealed) = ctx.seal(&path, key, value, rpc)?;
            let mut m = request("put");
            m.insert("path", Value::Text(path.clone()))
                .insert("value", Value::Bytes(bytes));
            let r = rpc(m)?;
            let (id, ts) = match r.get("entry") {
                Some(Value::Map(e)) => (
                    json!(e.text("id").unwrap_or("")),
                    json!(e.uint("ts").unwrap_or(0)),
                ),
                _ => (Json::Null, Json::Null),
            };
            Ok(
                json!({ "stored": true, "key": key, "encrypted": sealed, "nameHidden": is_hidden_path(&path),
                       "id": id, "ts": ts }),
            )
        }
        "memory_get" | "memory_provenance" => {
            let key = arg(args, "key")?;
            match ctx.find(key, name == "memory_provenance", rpc)? {
                Some(e) => {
                    let mut j = ctx.entry_json(&e, Some(key), name == "memory_get", rpc);
                    j["found"] = json!(true);
                    Ok(j)
                }
                None => Ok(json!({ "found": false, "key": key })),
            }
        }
        "memory_list" => {
            let prefix = args
                .get("prefix")
                .and_then(Json::as_str)
                .map(|p| p.trim_end_matches('/'))
                .filter(|p| !p.is_empty());
            let mut entries = Vec::new();
            match (prefix, ctx.hider()) {
                (None, _) => entries = list_at(None, rpc)?,
                (Some(p), Some(_)) => {
                    entries.extend(list_at(Some(&ctx.stored_path(p)), rpc)?);
                    entries.extend(list_at(Some(p), rpc)?);
                }
                (Some(p), None) => entries = list_at(Some(p), rpc)?,
            }
            let limit = args
                .get("limit")
                .and_then(Json::as_u64)
                .unwrap_or(LIST_PAGE)
                .clamp(1, LIST_MAX) as usize;
            let after = args.get("after").and_then(Json::as_str);
            let keys_only = args.get("keys_only").and_then(Json::as_bool) == Some(true);
            // One item per name: a name stored both plain (older) and hidden (newer)
            // shows once, as its newest entry.
            let mut by_key: std::collections::BTreeMap<String, Json> = Default::default();
            for e in &entries {
                let j = ctx.entry_json(e, None, !keys_only, rpc);
                let key = j["key"].as_str().unwrap_or("").to_owned();
                let newer = by_key
                    .get(&key)
                    .is_none_or(|old| j["ts"].as_u64() > old["ts"].as_u64());
                if newer {
                    by_key.insert(key, j);
                }
            }
            // A page in key order, so an agent's context never takes the whole memory.
            let total = by_key.len();
            let mut page: Vec<(String, Json)> = by_key
                .into_iter()
                .filter(|(k, _)| after.is_none_or(|a| k.as_str() > a))
                .take(limit + 1)
                .collect();
            let next = if page.len() > limit {
                page.truncate(limit);
                page.last().map(|(k, _)| k.clone())
            } else {
                None
            };
            let items: Vec<Json> = page.into_iter().map(|(_, j)| j).collect();
            Ok(json!({ "count": total, "items": items, "next": next }))
        }
        "memory_delete" => {
            let key = arg(args, "key")?;
            let path = match ctx.find(key, false, rpc)? {
                Some(e) => e.text("path").unwrap_or(key).to_owned(),
                None => ctx.stored_path(key),
            };
            let mut m = request("del");
            m.insert("path", Value::Text(path));
            rpc(m)?;
            Ok(json!({ "deleted": true, "key": key }))
        }
        other => Err(format!("unknown tool {other}")),
    }
}

/// Handles one JSON-RPC message; returns the response, if the message wants one.
fn handle(msg: &Json, ctx: &Ctx, rpc: Rpc) -> Option<Json> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Json::as_str).unwrap_or("");
    let result = match method {
        "initialize" => {
            let version = msg["params"]["protocolVersion"]
                .as_str()
                .unwrap_or(PROTOCOL_VERSION)
                .to_owned();
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "sameroot", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => {
            let name = msg["params"]["name"].as_str().unwrap_or("");
            let args = msg["params"].get("arguments").cloned().unwrap_or(json!({}));
            let (text, is_error) = match call_tool(name, &args, ctx, rpc) {
                Ok(j) => (j.to_string(), false),
                Err(e) => (e, true),
            };
            Ok(json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }))
        }
        _ if id.is_none() => return None, // a notification (e.g. notifications/initialized)
        other => Err(json!({ "code": -32601, "message": format!("method not found: {other}") })),
    };
    let id = id?;
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("sameroot-mcp {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("keygen") => {
            let path = key_path();
            match MemoryKey::create(&path) {
                Ok(k) => println!(
                    "created memory key {} at {} (mode 0600; copy it to your other devices, keep a backup)",
                    k.id_hex(),
                    path.display()
                ),
                Err(e) => {
                    eprintln!(
                        "keygen: {e} ({}); an existing key is never overwritten",
                        path.display()
                    );
                    std::process::exit(1);
                }
            }
            return;
        }
        Some("key-id") => {
            match MemoryKey::load(&key_path()) {
                Ok(Some(k)) => println!("{}", k.id_hex()),
                Ok(None) => {
                    eprintln!("no memory key at {}", key_path().display());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        _ => {}
    }
    let key = match MemoryKey::load(&key_path()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sameroot-mcp: memory key {}: {e}", key_path().display());
            std::process::exit(1);
        }
    };
    let ctx = Ctx {
        key,
        hide_names: std::env::var("SAMEROOT_PLAIN_NAMES").map_or(true, |v| v != "1"),
        allow_plaintext: std::env::var("SAMEROOT_ALLOW_PLAINTEXT").is_ok_and(|v| v == "1"),
        db_prefix: std::env::var("SAMEROOT_DB").unwrap_or_default(),
        db: RefCell::new(None),
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Json>(&line) {
            Ok(msg) => handle(&msg, &ctx, &node_rpc),
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null,
                                   "error": { "code": -32700, "message": format!("parse error: {e}") } })),
        };
        if let Some(r) = reply
            && (writeln!(stdout, "{r}").is_err() || stdout.flush().is_err())
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sameroot_seal::HIDDEN_ROOT;
    use std::collections::BTreeMap;

    const DB_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    /// A fake node: a key-value map behind the same RPC shapes as samerootd. It keeps
    /// the raw paths and bytes, so tests see what the ledger would hold.
    struct Fake {
        store: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                store: RefCell::new(BTreeMap::new()),
            }
        }

        fn call(&self, req: Map) -> Result<Map, String> {
            let entry = |path: &str, v: Option<&Vec<u8>>| {
                let mut e = Map::new();
                e.insert("path", Value::Text(path.into()))
                    .insert("ts", Value::Uint(1))
                    .insert("signer", Value::Text("aa".into()))
                    .insert("subspace", Value::Text("bb".into()))
                    .insert("id", Value::Text("cc".into()))
                    .insert("deleted", Value::Bool(false))
                    .insert_opt("value", v.cloned().map(Value::Bytes));
                Value::Map(e)
            };
            let mut out = sameroot_rpc::ok();
            match req.text("op").unwrap_or("") {
                "put" => {
                    let p = req.text("path").unwrap().to_owned();
                    self.store
                        .borrow_mut()
                        .insert(p.clone(), req.bytes("value").unwrap().to_vec());
                    out.insert("entry", entry(&p, None));
                }
                "get" => {
                    let p = req.text("path").unwrap();
                    let s = self.store.borrow();
                    out.insert("entry", s.get(p).map_or(Value::Null, |v| entry(p, Some(v))));
                }
                "list" => {
                    // Component-wise prefix, like the node.
                    let prefix = req.text("prefix").unwrap_or("");
                    let s = self.store.borrow();
                    out.insert(
                        "entries",
                        Value::Array(
                            s.iter()
                                .filter(|(k, _)| {
                                    prefix.is_empty()
                                        || *k == prefix
                                        || k.starts_with(&format!("{prefix}/"))
                                })
                                .map(|(k, v)| entry(k, Some(v)))
                                .collect(),
                        ),
                    );
                }
                "del" => {
                    self.store.borrow_mut().remove(req.text("path").unwrap());
                }
                "status" => {
                    let mut db = Map::new();
                    db.insert("id", Value::Text(DB_HEX.into()));
                    out.insert("device", Value::Text("dd".into()))
                        .insert("databases", Value::Array(vec![Value::Map(db)]));
                }
                other => return Err(format!("unknown op {other}")),
            }
            Ok(out)
        }
    }

    fn ctx(key: Option<MemoryKey>, hide_names: bool, allow_plaintext: bool) -> Ctx {
        Ctx {
            key,
            hide_names,
            allow_plaintext,
            db_prefix: "0707".into(),
            db: RefCell::new(None),
        }
    }

    fn call(c: &Ctx, rpc: Rpc, name: &str, args: Json) -> Json {
        let msg = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": name, "arguments": args } });
        let r = handle(&msg, c, rpc).unwrap();
        assert_eq!(r["result"]["isError"], json!(false), "{r}");
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    /// A fake status with a parent (followed) and its successor, both of origin
    /// `origin`.
    fn chain_status(origin: &str) -> impl Fn(Map) -> Result<Map, String> {
        let origin = origin.to_owned();
        move |req: Map| {
            assert_eq!(req.text("op"), Some("status"));
            let db = |id: &str, followed: bool| {
                let mut m = Map::new();
                m.insert("id", Value::Text(id.into()))
                    .insert("followed", Value::Bool(followed))
                    .insert("origin", Value::Text(origin.clone()));
                Value::Map(m)
            };
            let mut out = sameroot_rpc::ok();
            out.insert(
                "databases",
                Value::Array(vec![
                    db(&"aa".repeat(32), true),
                    db(&"bb".repeat(32), false),
                ]),
            );
            Ok(out)
        }
    }

    #[test]
    fn a_deleted_hidden_name_does_not_fall_back_to_an_older_plain_one() {
        let c = ctx(Some(MemoryKey::generate()), true, false);
        let hidden = c.stored_path("notes/a");
        assert_ne!(hidden, "notes/a");
        let rpc = move |req: Map| -> Result<Map, String> {
            let path = req.text("path").unwrap_or("").to_owned();
            let mut e = Map::new();
            e.insert("path", Value::Text(path.clone()))
                .insert("ts", Value::Uint(if path == hidden { 2 } else { 1 }))
                .insert("deleted", Value::Bool(path == hidden));
            let mut out = sameroot_rpc::ok();
            out.insert("entry", Value::Map(e));
            Ok(out)
        };
        assert!(c.find("notes/a", false, &rpc).unwrap().is_none());
        assert!(c.find("notes/a", true, &rpc).unwrap().is_some());
    }

    #[test]
    fn values_are_sealed_for_the_origin_of_the_chain() {
        let origin = "aa".repeat(32);
        let rpc = chain_status(&origin);
        for prefix in ["aa", "bb", ""] {
            let mut c = ctx(None, false, true);
            c.db_prefix = prefix.into();
            assert_eq!(c.db(&rpc).unwrap(), [0xaa; 32], "SAMEROOT_DB={prefix:?}");
        }
        // A sealed value carried into the successor opens with either prefix.
        let key = MemoryKey::generate();
        let sealed = key.seal(&[0xaa; 32], "notes/a", b"carried");
        let mut c = ctx(None, false, true);
        c.db_prefix = "bb".into();
        assert_eq!(
            key.open(&c.db(&rpc).unwrap(), "notes/a", &sealed).unwrap(),
            b"carried"
        );
    }

    #[test]
    fn memory_list_comes_in_pages_and_can_leave_out_values() {
        let f = Fake::new();
        let rpc = |m| f.call(m);
        let c = ctx(None, false, true);
        for i in 0..5 {
            call(
                &c,
                &rpc,
                "memory_set",
                json!({ "key": format!("k/{i}"), "value": i }),
            );
        }
        let first = call(&c, &rpc, "memory_list", json!({ "limit": 2 }));
        assert_eq!(first["count"], 5);
        let keys = |j: &Json| -> Vec<String> {
            j["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["key"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(keys(&first), ["k/0", "k/1"]);
        assert_eq!(first["next"], "k/1");
        let second = call(
            &c,
            &rpc,
            "memory_list",
            json!({ "limit": 2, "after": "k/1" }),
        );
        assert_eq!(keys(&second), ["k/2", "k/3"]);
        let last = call(
            &c,
            &rpc,
            "memory_list",
            json!({ "limit": 2, "after": "k/3" }),
        );
        assert_eq!(keys(&last), ["k/4"]);
        assert!(last["next"].is_null());
        let bare = call(&c, &rpc, "memory_list", json!({ "keys_only": true }));
        assert_eq!(bare["items"].as_array().unwrap().len(), 5);
        assert!(bare["items"][0].get("value").is_none(), "{bare}");
    }

    #[test]
    fn handshake_and_tool_list() {
        let f = Fake::new();
        let rpc = |m| f.call(m);
        let c = ctx(Some(MemoryKey::generate()), true, false);
        let init = handle(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } }),
            &c,
            &rpc,
        )
        .unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(
            handle(
                &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
                &c,
                &rpc
            )
            .is_none()
        );
        let list = handle(
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            &c,
            &rpc,
        )
        .unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 6);
        let unknown = handle(
            &json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" }),
            &c,
            &rpc,
        )
        .unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[test]
    fn names_are_hidden_and_values_sealed() {
        let f = Fake::new();
        let rpc = |m| f.call(m);
        let key = MemoryKey::generate();
        let raw = MemoryKey::from_bytes(&[0; 32]).unwrap(); // a different key, for the stranger
        let c = ctx(Some(key), true, false);
        call(
            &c,
            &rpc,
            "memory_set",
            json!({ "key": "notes/plan", "value": { "launch": "friday" } }),
        );
        call(
            &c,
            &rpc,
            "memory_set",
            json!({ "key": "notes/people", "value": ["ann"] }),
        );
        call(
            &c,
            &rpc,
            "memory_set",
            json!({ "key": "tasks/1", "value": "open" }),
        );
        // The ledger holds neither names nor values.
        let store = f.store.borrow().clone();
        assert_eq!(store.len(), 3);
        for (path, bytes) in &store {
            assert!(is_hidden_path(path), "{path}");
            assert!(!path.contains("notes") && !path.contains("plan") && !path.contains("tasks"));
            assert!(is_sealed(bytes));
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("notes") && !text.contains("friday"));
        }
        // Get, list by prefix, list all: the real names come back.
        let got = call(&c, &rpc, "memory_get", json!({ "key": "notes/plan" }));
        assert_eq!(
            (got["key"].clone(), got["value"].clone()),
            (json!("notes/plan"), json!({ "launch": "friday" }))
        );
        assert_eq!(got["nameHidden"], json!(true));
        let notes = call(&c, &rpc, "memory_list", json!({ "prefix": "notes/" }));
        let names: Vec<&str> = notes["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["key"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["notes/people", "notes/plan"]);
        assert_eq!(call(&c, &rpc, "memory_list", json!({}))["count"], 3);
        // Provenance and delete by the real name.
        assert_eq!(
            call(&c, &rpc, "memory_provenance", json!({ "key": "tasks/1" }))["key"],
            "tasks/1"
        );
        call(&c, &rpc, "memory_delete", json!({ "key": "tasks/1" }));
        assert_eq!(
            call(&c, &rpc, "memory_get", json!({ "key": "tasks/1" }))["found"],
            json!(false)
        );
        // A node without the key sees tokens and sealed values only.
        let stranger = ctx(Some(raw), true, false);
        let seen = call(&stranger, &rpc, "memory_list", json!({}));
        for item in seen["items"].as_array().unwrap() {
            assert!(item["key"].as_str().unwrap().starts_with(HIDDEN_ROOT));
            assert_eq!(item["value"]["readable"], json!(false));
        }
        assert_eq!(
            call(
                &stranger,
                &rpc,
                "memory_get",
                json!({ "key": "notes/plan" })
            )["found"],
            json!(false)
        );
    }

    #[test]
    fn earlier_entries_still_read() {
        let f = Fake::new();
        let rpc = |m| f.call(m);
        // Written before names were hidden: a plaintext value, and a sealed one.
        f.store
            .borrow_mut()
            .insert("legacy/plain".into(), b"{\"a\":1}".to_vec());
        let key = MemoryKey::generate();
        let sealed_only = ctx(Some(MemoryKey::from_bytes(&[3; 32]).unwrap()), false, false);
        call(
            &sealed_only,
            &rpc,
            "memory_set",
            json!({ "key": "legacy/sealed", "value": 2 }),
        );
        let c = ctx(Some(key), true, false);
        assert_eq!(
            call(&c, &rpc, "memory_get", json!({ "key": "legacy/plain" }))["value"],
            json!({ "a": 1 })
        );
        let both = ctx(Some(MemoryKey::from_bytes(&[3; 32]).unwrap()), true, false);
        let got = call(&both, &rpc, "memory_get", json!({ "key": "legacy/sealed" }));
        assert_eq!(
            (got["value"].clone(), got["nameHidden"].clone()),
            (json!(2), json!(false))
        );
        let listed = call(&both, &rpc, "memory_list", json!({ "prefix": "legacy" }));
        assert_eq!(listed["count"], 2);
    }

    #[test]
    fn without_a_key_writes_are_refused_unless_plaintext_is_allowed() {
        let f = Fake::new();
        let rpc = |m| f.call(m);
        let c = ctx(None, true, false);
        let msg = json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                          "params": { "name": "memory_set", "arguments": { "key": "a", "value": 1 } } });
        let r = handle(&msg, &c, &rpc).unwrap();
        assert_eq!(r["result"]["isError"], json!(true));
        assert!(f.store.borrow().is_empty(), "nothing reached the ledger");
        let plain = ctx(None, true, true);
        let stored = call(
            &plain,
            &rpc,
            "memory_set",
            json!({ "key": "a", "value": 1 }),
        );
        assert_eq!(
            (stored["encrypted"].clone(), stored["nameHidden"].clone()),
            (json!(false), json!(false))
        );
    }

    #[test]
    fn errors_are_tool_errors() {
        let f = Fake::new();
        let rpc = |m| f.call(m);
        let c = ctx(Some(MemoryKey::generate()), true, false);
        let msg = json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": { "name": "memory_get", "arguments": {} } });
        assert_eq!(
            handle(&msg, &c, &rpc).unwrap()["result"]["isError"],
            json!(true)
        );
        let down = |_: Map| -> Result<Map, String> { Err("no node".into()) };
        let r = handle(
            &json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": { "name": "memory_status", "arguments": {} } }),
            &c,
            &down,
        )
        .unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "no node");
    }
}
