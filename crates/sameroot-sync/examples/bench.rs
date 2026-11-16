//! Local measurements of the core, the store and replication (no network).
//!
//! `cargo run --release -p sameroot-sync --example bench [N]` — N is the store and
//! sync size (default 10,000). Prints one line per measurement.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sameroot_core::ledger::{Kind, Trie};
use sameroot_core::logic::{self, Inputs, V};
use sameroot_core::*;
use sameroot_store::Store;
use sameroot_sync::{MemValues, Session};
use tokio::sync::{mpsc, oneshot};

fn row(what: &str, value: String) {
    println!("{what:<60} {value}");
}

fn per(d: Duration, n: usize) -> String {
    let us = d.as_secs_f64() * 1e6 / n as f64;
    if us >= 1000.0 {
        format!("{:.2} ms/op", us / 1000.0)
    } else {
        format!("{us:.2} µs/op")
    }
}

fn rate(d: Duration, n: usize) -> String {
    format!("{:.0}/s", n as f64 / d.as_secs_f64())
}

fn id(n: u64) -> Digest {
    Digest::derive("bench id", &n.to_be_bytes())
}

struct World {
    owner: SecretKey,
    genesis: SignedGenesis,
}

fn world() -> World {
    let owner = SecretKey::from_seed([0x5a; 32]);
    let g = Genesis::new(
        "bench",
        owner.public(),
        logic::presets::own_subspace(),
        now_ms() - 60_000,
    );
    World {
        genesis: g.sign(&owner),
        owner,
    }
}

fn put(w: &World, i: u64, value: &[u8], ts: u64) -> SignedEntry {
    Header {
        db: w.genesis.id(),
        subspace: Subspace::Owner(w.owner.public()),
        path: Path::from_strs(["bench", &format!("{}", i % 2_000), &format!("{i}")]),
        op: Op::Put,
        ts,
        exp: None,
        value_size: value.len() as u64,
        value_hash: value_hash(value),
        target: None,
        signer: w.owner.public(),
        cert: None,
        work: 0,
    }
    .sign(&w.owner)
}

/// Admits an entry; its value goes to `values` (the node's blob store).
fn admit(s: &Store, values: &MemValues, e: &SignedEntry, v: &[u8]) {
    values.insert(v);
    s.insert_entry(e, &[], now_ms()).unwrap();
}

fn core_benches() {
    println!("== core");
    for n in [100_000usize, 1_000_000] {
        let t = Instant::now();
        let trie = Trie::build((0..n as u64).map(|i| (Kind::Entry, id(i))));
        let d = t.elapsed();
        row(
            &format!("trie: build {n} records"),
            format!("{d:.2?} ({})", rate(d, n)),
        );
        row(
            &format!("trie: nodes for {n} records"),
            format!("{}", trie.nodes().count()),
        );
        let proofs: Vec<_> = (0..1_000u64)
            .map(|i| (id(i * 7), trie.prove(&id(i * 7))))
            .collect();
        let levels =
            proofs.iter().map(|(_, p)| p.levels.len()).sum::<usize>() as f64 / proofs.len() as f64;
        row(
            &format!("trie: inclusion proof at {n}"),
            format!("{levels:.1} levels ≈ {:.0} B", levels * 128.0 + 33.0),
        );
        let root = trie.root();
        let t = Instant::now();
        for (i, p) in &proofs {
            assert!(p.proves_inclusion(&root, Kind::Entry, i));
        }
        row(
            &format!("trie: verify an inclusion proof at {n}"),
            per(t.elapsed(), proofs.len()),
        );
        let mut t2 = trie.clone();
        let t = Instant::now();
        for i in 0..10_000u64 {
            t2.insert(Kind::Entry, id(n as u64 + i));
        }
        row(
            &format!("trie: insert one record into {n}"),
            per(t.elapsed(), 10_000),
        );
    }

    let mut i = Inputs::new();
    i.insert("shared", V::Bool(false));
    i.insert("subspaceOwner", V::Bytes(vec![1; 32]));
    i.insert("chainRoot", V::Bytes(vec![1; 32]));
    let p = logic::presets::own_subspace();
    let t = Instant::now();
    for _ in 0..100_000 {
        assert!(logic::run(&p, &i));
    }
    row(
        "logic: run the own-subspace preset",
        per(t.elapsed(), 100_000),
    );

    let w = world();
    let db = w.genesis.id();
    let entries: Vec<SignedEntry> = (0..2_000)
        .map(|i| put(&w, i, b"v", now_ms() - 1_000))
        .collect();
    let none = |_: &Digest| None;
    let t = Instant::now();
    for e in &entries {
        verify_entry(&w.genesis.genesis, &db, e, &none).unwrap();
    }
    row(
        "admission: verify_entry (Ed25519 + contract)",
        per(t.elapsed(), entries.len()),
    );
}

fn store_benches(w: &World, n: usize) -> Vec<(SignedEntry, Vec<u8>)> {
    println!("== store ({n} entries, 100-byte values)");
    let db = w.genesis.id();
    let base = now_ms() - 30_000;
    let ops: Vec<(SignedEntry, Vec<u8>)> = (0..n as u64)
        .map(|i| {
            let v = format!("{i:0>100}").into_bytes();
            (put(w, i, &v, base + i), v)
        })
        .collect();

    let mem = Store::in_memory().unwrap();
    let values = MemValues::new();
    mem.add_database(&w.genesis).unwrap();
    let t = Instant::now();
    for (e, v) in &ops {
        admit(&mem, &values, e, v);
    }
    let d = t.elapsed();
    row(
        "store (memory): write value + admit entry",
        format!("{} ({})", per(d, n), rate(d, n)),
    );

    let dir = std::env::temp_dir().join(format!("sameroot-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    {
        let disk = Store::open(dir.join("bench.redb")).unwrap();
        disk.add_database(&w.genesis).unwrap();
        let m = n.min(2_000);
        let t = Instant::now();
        for (e, v) in &ops[..m] {
            admit(&disk, &values, e, v);
        }
        let d = t.elapsed();
        row(
            &format!("store (disk, first {m}): write value + admit entry"),
            format!("{} ({})", per(d, m), rate(d, m)),
        );
    }
    let _ = std::fs::remove_dir_all(&dir);

    let t = Instant::now();
    let s = mem.state(&db, now_ms()).unwrap();
    row(
        &format!("store: compute the state of {n} entries (cold)"),
        format!("{:.2?} ({} keys)", t.elapsed(), s.len()),
    );
    let t = Instant::now();
    mem.state(&db, now_ms()).unwrap();
    row(
        "store: read the state again (cached)",
        format!("{:.2?}", t.elapsed()),
    );
    let e = put(w, n as u64 + 1, b"after", now_ms() - 500);
    admit(&mem, &values, &e, b"after");
    let t = Instant::now();
    mem.get(&db, &e.header.subspace, &e.header.path, now_ms())
        .unwrap();
    row(
        "store: first read after a write (state recomputed)",
        format!("{:.2?}", t.elapsed()),
    );
    ops
}

/// Connects two replicas; returns A's session handle (the node's write path rings it).
async fn connect(
    a: (Arc<Mutex<Store>>, MemValues),
    b: (Arc<Mutex<Store>>, MemValues),
    db: Digest,
) -> Session {
    let (x, y) = tokio::io::duplex(1 << 20);
    let mut handles = Vec::new();
    for (stream, (store, values)) in [(x, a), (y, b)] {
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = sameroot_sync::run(stream, store, values, db, ev_tx, ready_tx).await;
        });
        tokio::spawn(async move { while ev_rx.recv().await.is_some() {} });
        handles.push(ready_rx.await.unwrap());
    }
    handles.swap_remove(0)
}

async fn until(f: impl Fn() -> bool) {
    while !f() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn sync_benches(w: &World, ops: &[(SignedEntry, Vec<u8>)]) {
    let n = ops.len();
    println!("== sync over an in-process stream ({n} entries)");
    let db = w.genesis.id();
    let a = Arc::new(Mutex::new(Store::in_memory().unwrap()));
    let a_values = MemValues::new();
    {
        let s = a.lock().unwrap();
        s.add_database(&w.genesis).unwrap();
        for (e, v) in ops {
            admit(&s, &a_values, e, v);
        }
    }
    // A fresh replica that doesn't even have the genesis.
    let b = Arc::new(Mutex::new(Store::in_memory().unwrap()));
    let b_values = MemValues::new();
    let t = Instant::now();
    let session = connect(
        (a.clone(), a_values.clone()),
        (b.clone(), b_values.clone()),
        db,
    )
    .await;
    let root = a.lock().unwrap().root(&db).unwrap();
    until(|| b.lock().unwrap().root(&db).ok() == Some(root)).await;
    let d = t.elapsed();
    row(
        &format!("cold sync: {n} records to a fresh replica"),
        format!("{d:.2?} ({})", rate(d, n)),
    );
    // The values are small, so they ride inline with their records.
    until(|| {
        ops.iter()
            .all(|(e, _)| b_values.contains(&e.header.value_hash))
    })
    .await;
    row(
        "cold sync: until every (inline) value has arrived too",
        format!("{:.2?}", t.elapsed()),
    );

    // One new record on A, rung through the session as the daemon does: after the
    // replicas were idle for over a second, and back to back (roots are coalesced to
    // one per second).
    for (label, pause) in [("after idle", 1_200u64), ("back to back", 0)] {
        let mut samples = Vec::new();
        for k in 0..7u64 {
            tokio::time::sleep(Duration::from_millis(pause)).await;
            let e = put(w, 10_000_000 + pause * 100 + k, b"late", now_ms() - 100);
            let t = Instant::now();
            admit(&a.lock().unwrap(), &a_values, &e, b"late");
            session.resync();
            let id = e.id();
            until(|| b.lock().unwrap().record(&db, &id).unwrap().is_some()).await;
            samples.push(t.elapsed());
        }
        samples.sort();
        row(
            &format!("incremental ({label}): one record reaches the replica"),
            format!(
                "median {:.2?}, max {:.2?}",
                samples[samples.len() / 2],
                samples[samples.len() - 1]
            ),
        );
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    core_benches();
    let w = world();
    let ops = store_benches(&w, n);
    sync_benches(&w, &ops).await;
}
