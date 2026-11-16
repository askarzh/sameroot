//! Helpers for the end-to-end tests: real `samerootd` processes on this machine,
//! connected directly (no relays), driven through their local RPC.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sameroot_core::cbor::{Map, Value};
use sameroot_core::*;
use sameroot_rpc::{Fields, request};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A node process with its own home; killed when dropped.
pub struct Daemon {
    pub home: PathBuf,
    child: Option<Child>,
    /// Extra environment for the process.
    pub env: Vec<(String, String)>,
}

impl Daemon {
    pub fn new() -> Daemon {
        let home = std::env::temp_dir().join(format!(
            "sameroot-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        Daemon {
            home,
            child: None,
            env: Vec::new(),
        }
    }

    pub fn start(&mut self) {
        let log = std::fs::File::create(self.home.join("log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_samerootd"))
            .env("SAMEROOT_HOME", &self.home)
            .env("SAMEROOT_RELAY", "none")
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.try_call(request("status")).is_err() {
            assert!(
                Instant::now() < deadline,
                "node didn't start: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stops the node as systemd does, with SIGTERM; kills it if it doesn't exit.
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &c.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(10);
            while c.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.home.join("log")).unwrap_or_default()
    }

    pub fn try_call(&self, req: Map) -> std::io::Result<Map> {
        sameroot_rpc::call(&self.home.join("samerootd.sock"), &req)
    }

    pub fn call(&self, req: Map) -> Map {
        let r = self.try_call(req).unwrap();
        assert_eq!(
            r.flag("ok"),
            Some(true),
            "rpc failed: {:?}",
            r.text("error")
        );
        r
    }

    pub fn device(&self) -> PublicKey {
        PublicKey::from_hex(self.call(request("status")).text("device").unwrap()).unwrap()
    }

    pub fn put(&self, path: &str, value: &[u8]) {
        let mut m = request("put");
        m.insert("path", Value::Text(path.into()))
            .insert("value", Value::Bytes(value.to_vec()));
        self.call(m);
    }

    /// The current value at `path` in `subspace`, if this node holds it.
    pub fn get(&self, subspace: &PublicKey, path: &str) -> Option<Vec<u8>> {
        let mut m = request("get");
        m.insert("path", Value::Text(path.into()))
            .insert("subspace", Value::Text(subspace.to_hex()));
        // Before the genesis arrives the node doesn't know the database yet.
        let r = self.try_call(m).ok()?;
        match r.get("entry") {
            Some(Value::Map(e)) => e.bytes("value").map(<[u8]>::to_vec),
            _ => None,
        }
    }

    pub fn values_missing(&self) -> u64 {
        let r = self.call(request("status"));
        match r.list("databases").unwrap_or(&[]).first() {
            Some(Value::Map(d)) => d.uint("valuesMissing").unwrap_or(0),
            _ => 0,
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// A database whose owner writes in its own subspace, allowing values up to
/// `max_value` bytes.
pub fn database(owner: &SecretKey, max_value: u64) -> SignedGenesis {
    let mut g = Genesis::new(
        "e2e",
        owner.public(),
        logic::presets::own_subspace(),
        now_ms() - 60_000,
    );
    g.limits.max_value = max_value;
    g.sign(owner)
}

pub fn delegate(owner: &SecretKey, db: Digest, device: PublicKey) -> SignedCert {
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
        not_before: now - 60_000,
        not_after: now + 3_600_000,
        name: None,
        endpoint: None,
    }
    .sign(owner)
}

/// Deterministic bytes that don't compress or repeat.
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut h = value_hash(&[seed; 32]);
    while out.len() < len {
        out.extend_from_slice(&h.0);
        h = value_hash(&h.0);
    }
    out.truncate(len);
    out
}

pub fn wait_for(what: &str, secs: u64, mut done: impl FnMut() -> bool, logs: &[&Daemon]) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        if Instant::now() >= deadline {
            for d in logs {
                eprintln!("--- {}\n{}", d.home.display(), d.log());
            }
            panic!("timed out: {what}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl Daemon {
    /// The paths `list` returns, as `subspace/path`; `all` lists every subspace.
    pub fn list(&self, all: bool) -> Vec<String> {
        let mut m = request("list");
        if all {
            m.insert("all", Value::Bool(true));
        }
        self.call(m)
            .list("entries")
            .unwrap_or(&[])
            .iter()
            .filter_map(|e| match e {
                Value::Map(e) => Some(format!(
                    "{}/{}",
                    &e.text("subspace").unwrap_or("?")[..8],
                    e.text("path").unwrap_or("?")
                )),
                _ => None,
            })
            .collect()
    }

    pub fn join(&self, invite: String) {
        let mut j = request("join");
        j.insert("invite", Value::Text(invite));
        self.call(j);
    }

    pub fn invite(&self, db: &Digest) -> String {
        let mut m = request("invite");
        m.insert("db", Value::Text(db.to_hex()));
        self.call(m).text("invite").unwrap().to_owned()
    }
}

impl Daemon {
    /// Writes as one of the node's agents.
    pub fn put_as(&self, agent: &str, path: &str, value: &[u8]) -> Map {
        let mut m = request("put");
        m.insert("path", Value::Text(path.into()))
            .insert("value", Value::Bytes(value.to_vec()))
            .insert("agent", Value::Text(agent.into()));
        self.try_call(m).unwrap()
    }

    pub fn certs(&self) -> Vec<Map> {
        self.call(request("certs"))
            .list("certs")
            .unwrap_or(&[])
            .iter()
            .filter_map(|c| match c {
                Value::Map(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }
}
