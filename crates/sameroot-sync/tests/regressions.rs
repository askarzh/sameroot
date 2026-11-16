//! Transport regressions carried over from the design 0002 review, and the design
//! 0004 records, for protocol v5.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sameroot_core::ledger::{Kind, Trie};
use sameroot_core::*;
use sameroot_store::{Outcome, Store};
use sameroot_sync::{Event, MemValues, Session, run};
use tokio::sync::{mpsc, oneshot};

struct World {
    owner: SecretKey,
    genesis: SignedGenesis,
}

fn world() -> World {
    let owner = SecretKey::from_seed([0x42; 32]);
    let mut g = Genesis::new(
        "regressions",
        owner.public(),
        logic::presets::own_subspace(),
        now_ms() - 60_000,
    );
    g.limits.max_value = 2 << 20;
    World {
        genesis: g.sign(&owner),
        owner,
    }
}

fn put(w: &World, key: &str, value: &[u8], ts: u64) -> SignedEntry {
    Header {
        db: w.genesis.id(),
        subspace: Subspace::Owner(w.owner.public()),
        path: Path::parse(key).unwrap(),
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

/// A replica: its store, its values, and the value hashes its sessions reported
/// missing.
#[derive(Clone)]
struct Replica {
    store: Arc<Mutex<Store>>,
    values: MemValues,
    missing: Arc<Mutex<Vec<Digest>>>,
}

fn replica(w: &World) -> Replica {
    let s = Store::in_memory().unwrap();
    s.add_database(&w.genesis).unwrap();
    Replica {
        store: Arc::new(Mutex::new(s)),
        values: MemValues::new(),
        missing: Arc::default(),
    }
}

fn write(r: &Replica, e: &SignedEntry, value: &[u8]) {
    r.values.insert(value);
    r.store
        .lock()
        .unwrap()
        .insert_entry(e, &[], now_ms())
        .unwrap();
}

async fn connect(a: &Replica, b: &Replica, db: Digest, buffer: usize) -> (Session, Session) {
    let (x, y) = tokio::io::duplex(buffer);
    let mut handles = Vec::new();
    for (stream, r) in [(x, a.clone()), (y, b.clone())] {
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (store, values) = (r.store.clone(), r.values.clone());
        tokio::spawn(async move {
            if let Err(e) = run(stream, store, values, db, ev_tx, ready_tx).await {
                eprintln!("session ended: {e}");
            }
        });
        tokio::spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                if let Event::MissingValue { hash, .. } = ev {
                    r.missing.lock().unwrap().push(hash);
                }
            }
        });
        handles.push(ready_rx.await.unwrap());
    }
    let b = handles.pop().unwrap();
    (handles.pop().unwrap(), b)
}

/// Waits until both replicas have the same root and `b` holds every value `a` holds.
async fn converge(a: &Replica, b: &Replica, db: &Digest, values: &[Digest], secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let (ra, rb) = (
            a.store.lock().unwrap().root(db).unwrap(),
            b.store.lock().unwrap().root(db).unwrap(),
        );
        let have = values.iter().all(|h| b.values.contains(h));
        if ra == rb && have {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no convergence: {} vs {} records",
            ra.0,
            rb.0
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Small values ride inline with their records, in as many frames as it takes; a
/// value above the inline limit stays out of the session and is reported missing,
/// once, for the node to fetch from a blob store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_values_inline_large_ones_reported() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let base = now_ms() - 30_000;
    let mut small = Vec::new();
    // 300 values of 60 KiB: over two response budgets of inline values.
    for i in 0..300u64 {
        let value = vec![i as u8; 60 * 1024];
        let e = put(&w, &format!("small/{i}"), &value, base + i);
        small.push(e.header.value_hash);
        write(&a, &e, &value);
    }
    let mut large = Vec::new();
    for i in 0..4u64 {
        let value = vec![i as u8; 1_500_000];
        let e = put(&w, &format!("large/{i}"), &value, base + 1000 + i);
        large.push(e.header.value_hash);
        write(&a, &e, &value);
    }
    let b = replica(&w);
    let (_sa, _sb) = connect(&a, &b, db, 1 << 20).await;
    converge(&a, &b, &db, &small, 120).await;
    // The reports trail the records by a moment.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while b.missing.lock().unwrap().len() < large.len() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "missing values not reported"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut reported = b.missing.lock().unwrap().clone();
    reported.sort();
    large.sort();
    assert_eq!(reported, large, "each large value reported once");
    assert!(large.iter().all(|h| !b.values.contains(h)));
}

/// Frames fragmented by a tiny stream buffer, with resyncs firing all the time, must
/// not desynchronise the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fragmented_frames_survive_constant_resyncs() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let base = now_ms() - 30_000;
    for i in 0..1_500u64 {
        write(
            &a,
            &put(&w, &format!("frag/{i}"), b"value", base + i),
            b"value",
        );
    }
    let b = replica(&w);
    let (sa, sb) = connect(&a, &b, db, 64).await;
    let spam = tokio::spawn(async move {
        for _ in 0..4_000 {
            sa.resync();
            sb.resync();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    converge(&a, &b, &db, &[value_hash(b"value")], 120).await;
    spam.abort();
}

/// Pushed records arrive at once, even back to back (finding 1–2 of the first
/// measurements: walks plus one-second root coalescing took 1.6 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pushed_records_arrive_at_once() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let b = replica(&w);
    let base = now_ms() - 30_000;
    for i in 0..500u64 {
        write(&a, &put(&w, &format!("old/{i}"), b"v", base + i), b"v");
    }
    let (sa, _sb) = connect(&a, &b, db, 1 << 20).await;
    converge(&a, &b, &db, &[], 60).await;
    let mut worst = Duration::ZERO;
    for k in 0..20u64 {
        let e = put(&w, &format!("new/{k}"), b"fresh", now_ms() - 10);
        let t = tokio::time::Instant::now();
        write(&a, &e, b"fresh");
        sa.push(vec![e.id()]);
        while b
            .store
            .lock()
            .unwrap()
            .record(&db, &e.id())
            .unwrap()
            .is_none()
        {
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "record {k} didn't arrive"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        worst = worst.max(t.elapsed());
    }
    assert!(
        worst < Duration::from_millis(300),
        "slowest pushed record took {worst:?}"
    );
}

/// When the peer goes away, the session reports itself closed even while its handle
/// is retained (so the node redials).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_closes_when_the_peer_goes_away() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let (x, y) = tokio::io::duplex(1 << 16);
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = run(x, a.store, a.values, db, ev_tx, ready_tx).await;
    });
    tokio::spawn(async move { while ev_rx.recv().await.is_some() {} });
    let session = ready_rx.await.unwrap();
    assert!(session.is_open());
    drop(y);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while session.is_open() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "session still reports open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Design 0004 records replicate to a fresh replica: a void with its chain and keep
/// list, a bare key's self-void, and a forward. Both sides end with the same record
/// root, ledger commitment, state and keep list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voids_with_keep_lists_and_forwards_replicate() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let device = SecretKey::from_seed([0x43; 32]);
    let cert = Cert {
        issuer: w.owner.public(),
        subject: device.public(),
        parent: None,
        db,
        area: Area {
            subspace: Subspace::Owner(w.owner.public()),
            path_prefix: Path::default(),
            ops: vec![Op::Put],
        },
        not_before: 0,
        not_after: u64::MAX,
        name: None,
        endpoint: None,
    }
    .sign(&w.owner);
    let base = now_ms() - 30_000;
    let by_device = |key: &str, ts: u64| {
        Header {
            cert: Some(cert.id()),
            signer: device.public(),
            ..put(&w, key, b"v", ts).header
        }
        .sign(&device)
    };
    let (honest, forged) = (by_device("d/honest", base), by_device("d/forged", base + 1));
    a.values.insert(b"v");
    for e in [&honest, &forged] {
        a.store
            .lock()
            .unwrap()
            .insert_entry(e, std::slice::from_ref(&cert), now_ms())
            .unwrap();
    }
    let keep = vec![honest.id()];
    let void = Void {
        keep: Some(Keep {
            root: Trie::build([(Kind::Entry, honest.id())]).root(),
            count: 1,
        }),
        ..Void::of_cert(db, cert.id(), w.owner.public())
    }
    .sign(&w.owner);
    // own-subspace: a bare key writes its own subspace, then kills itself.
    let bare = SecretKey::from_seed([0x44; 32]);
    let bare_put = Header {
        subspace: Subspace::Owner(bare.public()),
        signer: bare.public(),
        ..put(&w, "b/1", b"v", base + 2).header
    }
    .sign(&bare);
    let kill = Void::of_key(db, bare.public()).sign(&bare);
    {
        let st = a.store.lock().unwrap();
        assert_eq!(
            st.insert_void(&void, &[], Some(&keep)).unwrap(),
            Outcome::Added
        );
        st.insert_entry(&bare_put, &[], now_ms()).unwrap();
        assert_eq!(st.insert_void(&kill, &[], None).unwrap(), Outcome::Added);
        let forward = Forward {
            db,
            successor: Digest([7; 32]),
            owner: w.owner.public(),
            cut_root: st.ledger_root(&db).unwrap(),
        }
        .sign(&w.owner);
        assert_eq!(st.insert_forward(&forward).unwrap(), Outcome::Added);
    }
    let b = replica(&w);
    let (_sa, _sb) = connect(&a, &b, db, 1 << 20).await;
    converge(&a, &b, &db, &[], 60).await;
    let (sa, sb) = (a.store.lock().unwrap(), b.store.lock().unwrap());
    assert_eq!(sa.root(&db).unwrap(), sb.root(&db).unwrap());
    assert_eq!(sa.ledger_root(&db).unwrap(), sb.ledger_root(&db).unwrap());
    assert_eq!(sb.keep_list(&void.id()).unwrap(), Some(keep));
    assert_eq!(
        sa.state(&db, now_ms()).unwrap(),
        sb.state(&db, now_ms()).unwrap()
    );
    let sub = Subspace::Owner(w.owner.public());
    let now = now_ms();
    assert!(
        sb.get(&db, &sub, &Path::parse("d/honest").unwrap(), now)
            .unwrap()
            .is_some()
    );
    assert!(
        sb.get(&db, &sub, &Path::parse("d/forged").unwrap(), now)
            .unwrap()
            .is_none()
    );
    let bare_sub = Subspace::Owner(bare.public());
    assert!(
        sb.get(&db, &bare_sub, &Path::parse("b/1").unwrap(), now)
            .unwrap()
            .is_none()
    );
    assert_eq!(sb.forwards(&db).unwrap().len(), 1);
}

/// A peer that speaks the protocol frame by frame, to script misbehaviour.
struct RawPeer {
    stream: tokio::io::DuplexStream,
}

impl RawPeer {
    async fn send(&mut self, v: cbor::Value) {
        use tokio::io::AsyncWriteExt;
        let b = cbor::encode(&v);
        self.stream
            .write_all(&(b.len() as u32).to_be_bytes())
            .await
            .unwrap();
        self.stream.write_all(&b).await.unwrap();
    }

    async fn recv(&mut self) -> cbor::Map {
        use tokio::io::AsyncReadExt;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await.unwrap();
        let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
        self.stream.read_exact(&mut b).await.unwrap();
        match cbor::decode(&b).unwrap() {
            cbor::Value::Map(m) => m,
            _ => panic!("frame is not a map"),
        }
    }

    /// The next frame of type `t`, skipping others.
    async fn next(&mut self, t: &str) -> cbor::Map {
        loop {
            let m = self.recv().await;
            if matches!(m.get("t"), Some(cbor::Value::Text(x)) if x == t) {
                return m;
            }
        }
    }

    /// Opens a session with replica `r` and says hello.
    async fn connect(r: &Replica, db: Digest) -> RawPeer {
        let (x, y) = tokio::io::duplex(1 << 20);
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let (ready_tx, _ready_rx) = oneshot::channel();
        let (store, values) = (r.store.clone(), r.values.clone());
        tokio::spawn(async move {
            let _ = run(x, store, values, db, ev_tx, ready_tx).await;
        });
        tokio::spawn(async move { while ev_rx.recv().await.is_some() {} });
        let mut peer = RawPeer { stream: y };
        let mut hello = cbor::Map::new();
        hello
            .insert("t", cbor::Value::Text("hello".into()))
            .insert("v", cbor::Value::Uint(sameroot_sync::PROTOCOL_VERSION))
            .insert("nonce", cbor::Value::Bytes(vec![0; 16]))
            .insert("db", cbor::Value::Bytes(db.0.to_vec()))
            .insert("needGenesis", cbor::Value::Bool(false))
            .insert("clock", cbor::Value::Uint(now_ms()));
        peer.send(cbor::Value::Map(hello)).await;
        peer
    }
}

fn frame(t: &str, field: &str, items: Vec<cbor::Value>) -> cbor::Value {
    let mut m = cbor::Map::new();
    m.insert("t", cbor::Value::Text(t.into()))
        .insert(field, cbor::Value::Array(items));
    cbor::Value::Map(m)
}

fn records_in(m: &cbor::Map) -> Vec<cbor::Map> {
    match m.get("records") {
        Some(cbor::Value::Array(a)) => a
            .iter()
            .filter_map(|v| match v {
                cbor::Value::Map(m) => Some(m.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// A `want` that repeats one id 1,024 times gets that record once (review finding:
/// responses were built whole, so repeated ids multiplied their size).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_wants_are_answered_once() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let e = put(&w, "k", b"v", now_ms() - 1_000);
    write(&a, &e, b"v");
    let mut peer = RawPeer::connect(&a, db).await;
    let id = cbor::Value::Bytes(e.id().0.to_vec());
    peer.send(frame("want", "ids", vec![id; 1024])).await;
    let mut got = 0;
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), peer.next("records"))
            .await
            .expect("records arrive");
        got += records_in(&m).len();
        if matches!(m.get("done"), Some(cbor::Value::Bool(true))) {
            break;
        }
    }
    assert_eq!(got, 1);
}

/// A void that arrives without its keep list is pending, and the session asks for it
/// again; when the peer then sends it with the list, it is admitted (review finding:
/// records missing a dependency were dropped until the roots changed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_missing_a_dependency_are_asked_for_again() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    let device = SecretKey::from_seed([0x45; 32]);
    let cert = Cert {
        issuer: w.owner.public(),
        subject: device.public(),
        parent: None,
        db,
        area: Area {
            subspace: Subspace::Owner(w.owner.public()),
            path_prefix: Path::default(),
            ops: vec![Op::Put],
        },
        not_before: 0,
        not_after: u64::MAX,
        name: None,
        endpoint: None,
    }
    .sign(&w.owner);
    let kept = vec![Digest([1; 32])];
    let void = Void {
        keep: Some(Keep {
            root: Trie::build([(Kind::Entry, kept[0])]).root(),
            count: 1,
        }),
        ..Void::of_cert(db, cert.id(), w.owner.public())
    }
    .sign(&w.owner);
    let item = |with_list: bool| {
        let mut m = cbor::Map::new();
        m.insert("k", cbor::Value::Uint(1))
            .insert("r", cbor::Value::Bytes(void.encode()))
            .insert(
                "c",
                cbor::Value::Array(vec![cbor::Value::Bytes(cert.encode())]),
            );
        if with_list {
            m.insert("kl", cbor::Value::Bytes(kept[0].0.to_vec()));
        }
        cbor::Value::Map(m)
    };
    let mut peer = RawPeer::connect(&a, db).await;
    peer.send(frame("records", "records", vec![item(false)]))
        .await;
    // The session asks for the void again within a few ticks.
    let want = tokio::time::timeout(Duration::from_secs(15), peer.next("want"))
        .await
        .expect("the void is asked for again");
    assert!(matches!(
        want.get("ids"),
        Some(cbor::Value::Array(ids)) if ids.contains(&cbor::Value::Bytes(void.id().0.to_vec()))
    ));
    assert!(
        a.store
            .lock()
            .unwrap()
            .record(&db, &void.id())
            .unwrap()
            .is_none()
    );
    peer.send(frame("records", "records", vec![item(true)]))
        .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while a
        .store
        .lock()
        .unwrap()
        .record(&db, &void.id())
        .unwrap()
        .is_none()
    {
        assert!(tokio::time::Instant::now() < deadline, "void admitted");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        a.store.lock().unwrap().keep_list(&void.id()).unwrap(),
        Some(kept)
    );
}

/// A peer that stops reading and then breaks the protocol: the session ends within
/// its shutdown grace instead of waiting forever on a blocked write (review finding).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_stops_reading_cannot_hold_the_session() {
    use tokio::io::AsyncWriteExt;
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    // Enough records that their answer can't fit a tiny stream buffer.
    let base = now_ms() - 30_000;
    let mut ids = Vec::new();
    for i in 0..200u64 {
        let e = put(&w, &format!("k/{i}"), b"value", base + i);
        ids.push(cbor::Value::Bytes(e.id().0.to_vec()));
        write(&a, &e, b"value");
    }
    let (x, mut y) = tokio::io::duplex(256);
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let (ready_tx, _ready) = oneshot::channel();
    let (store, values) = (a.store.clone(), a.values.clone());
    let session = tokio::spawn(async move { run(x, store, values, db, ev_tx, ready_tx).await });
    tokio::spawn(async move { while ev_rx.recv().await.is_some() {} });
    let frame_bytes = |v: cbor::Value| {
        let b = cbor::encode(&v);
        let mut out = (b.len() as u32).to_be_bytes().to_vec();
        out.extend(b);
        out
    };
    let mut hello = cbor::Map::new();
    hello
        .insert("t", cbor::Value::Text("hello".into()))
        .insert("v", cbor::Value::Uint(sameroot_sync::PROTOCOL_VERSION))
        .insert("nonce", cbor::Value::Bytes(vec![0; 16]))
        .insert("db", cbor::Value::Bytes(db.0.to_vec()))
        .insert("needGenesis", cbor::Value::Bool(false))
        .insert("clock", cbor::Value::Uint(now_ms()));
    y.write_all(&frame_bytes(cbor::Value::Map(hello)))
        .await
        .unwrap();
    y.write_all(&frame_bytes(frame("want", "ids", ids)))
        .await
        .unwrap();
    let mut bogus = cbor::Map::new();
    bogus.insert("t", cbor::Value::Text("bogus".into()));
    y.write_all(&frame_bytes(cbor::Value::Map(bogus)))
        .await
        .unwrap();
    // The peer never reads again. The session must still end.
    let ended = tokio::time::timeout(
        sameroot_sync::SHUTDOWN_GRACE + Duration::from_secs(5),
        session,
    )
    .await;
    assert!(
        ended.is_ok(),
        "the session is held by a peer that doesn't read"
    );
    drop(y);
}

/// A retired database is only its stub: a straggler that connects learns the
/// forward (with the genesis, if it had none), its own records don't flow back, and
/// the session ends (design 0004 §8.3 step 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retired_database_hands_out_its_forward() {
    let w = world();
    let db = w.genesis.id();
    let a = replica(&w);
    write(&a, &put(&w, "k/old", b"old", now_ms() - 10_000), b"old");
    let forward = {
        let st = a.store.lock().unwrap();
        let f = Forward {
            db,
            successor: Digest([8; 32]),
            owner: w.owner.public(),
            cut_root: st.ledger_root(&db).unwrap(),
        }
        .sign(&w.owner);
        st.insert_forward(&f).unwrap();
        st.retire(&db, now_ms()).unwrap();
        f
    };
    let stub_root = a.store.lock().unwrap().root(&db).unwrap();

    // A straggler with the genesis and a late write of its own.
    let b = replica(&w);
    write(&b, &put(&w, "k/late", b"late", now_ms()), b"late");
    // One without anything.
    let c = Replica {
        store: Arc::new(Mutex::new(Store::in_memory().unwrap())),
        values: MemValues::new(),
        missing: Arc::default(),
    };
    for r in [&b, &c] {
        let (sa, sb) = connect(&a, r, db, 1 << 20).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while r.store.lock().unwrap().forwards(&db).unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "no forward");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            r.store.lock().unwrap().forwards(&db).unwrap(),
            vec![forward.clone()]
        );
        while sa.is_open() || sb.is_open() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the session stays open"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    assert!(c.store.lock().unwrap().genesis(&db).unwrap().is_some());
    assert_eq!(a.store.lock().unwrap().root(&db).unwrap(), stub_root);
    assert_eq!(
        b.store.lock().unwrap().root(&db).unwrap().0,
        2,
        "its write and the forward"
    );
}

/// A record dated ahead of the receiver's clock is deferred with its inline value,
/// and admitted when its time comes, without fetching the value again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_entry_keeps_its_inline_value() {
    let owner = SecretKey::from_seed([0x45; 32]);
    let mut g = Genesis::new(
        "deferred",
        owner.public(),
        logic::presets::own_subspace(),
        now_ms() - 60_000,
    );
    g.limits.ts_skew = 0;
    let w = World {
        genesis: g.sign(&owner),
        owner,
    };
    let db = w.genesis.id();
    let a = replica(&w);
    let soon = now_ms() + 3_000;
    let e = put(&w, "k/soon", b"from the near future", soon);
    a.values.insert(b"from the near future");
    // A's clock is "ahead": it admits the record now.
    a.store
        .lock()
        .unwrap()
        .insert_entry(&e, &[], soon + 1)
        .unwrap();
    let b = replica(&w);
    let (_sa, _sb) = connect(&a, &b, db, 1 << 20).await;
    // B defers it, but keeps the value that came inline.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !b.values.contains(&value_hash(b"from the near future")) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the inline value of a deferred entry was dropped"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(b.store.lock().unwrap().root(&db).unwrap().0, 0, "deferred");
    // Its time comes: admitted on a session tick, value already here.
    converge(&a, &b, &db, &[value_hash(b"from the near future")], 20).await;
    assert!(b.missing.lock().unwrap().is_empty(), "no fetch needed");
}

/// A node whose hash isn't the one the peer's root promised is not walked: a peer
/// can't make a session want records that aren't under the root it announced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nodes_that_do_not_match_the_announced_root_are_not_walked() {
    let w = world();
    let db = w.genesis.id();
    let r = replica(&w);
    let mut peer = RawPeer::connect(&r, db).await;
    let honest = put(&w, "k/honest", b"h", now_ms());
    let other = put(&w, "k/other", b"o", now_ms());
    let announced = Trie::build([(Kind::Entry, honest.id())]);
    let served = Trie::build([(Kind::Entry, other.id())]);
    let mut root = cbor::Map::new();
    root.insert("t", cbor::Value::Text("root".into()))
        .insert("hash", cbor::Value::Bytes(announced.root().0.to_vec()))
        .insert("count", cbor::Value::Uint(1));
    peer.send(cbor::Value::Map(root)).await;
    let get = peer.next("getNodes").await;
    assert!(matches!(get.get("paths"), Some(cbor::Value::Array(p)) if !p.is_empty()));
    let mut item = cbor::Map::new();
    item.insert("p", cbor::Value::Bytes(Vec::new()))
        .insert("n", cbor::Value::Bytes(served.node(&[]).unwrap().encode()));
    let mut nodes = cbor::Map::new();
    nodes
        .insert("t", cbor::Value::Text("nodes".into()))
        .insert("nodes", cbor::Value::Array(vec![cbor::Value::Map(item)]))
        .insert("done", cbor::Value::Bool(true));
    peer.send(cbor::Value::Map(nodes)).await;
    // The session must not ask for the record under the forged node.
    let asked = tokio::time::timeout(Duration::from_secs(3), peer.next("want")).await;
    if let Ok(m) = asked {
        let wanted_other = match m.get("ids") {
            Some(cbor::Value::Array(ids)) => ids
                .iter()
                .any(|v| matches!(v, cbor::Value::Bytes(b) if b.as_slice() == other.id().0)),
            _ => false,
        };
        assert!(
            !wanted_other,
            "wanted a record under a node that doesn't match the root"
        );
    }
}

/// Frames from an untrusted peer: any sequence of maps with real or made-up types and
/// random fields may end the session with an error, never with a panic.
#[test]
fn random_frames_never_panic_a_session() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    fn field() -> impl Strategy<Value = cbor::Value> {
        prop_oneof![
            any::<u64>().prop_map(cbor::Value::Uint),
            proptest::collection::vec(any::<u8>(), 0..70).prop_map(cbor::Value::Bytes),
            "[a-z]{0,8}".prop_map(cbor::Value::Text),
            any::<bool>().prop_map(cbor::Value::Bool),
            proptest::collection::vec(
                prop_oneof![
                    proptest::collection::vec(any::<u8>(), 0..40).prop_map(cbor::Value::Bytes),
                    any::<u64>().prop_map(cbor::Value::Uint),
                ],
                0..5
            )
            .prop_map(cbor::Value::Array),
        ]
    }
    let kinds = prop_oneof![
        Just("root"),
        Just("getRoot"),
        Just("getNodes"),
        Just("nodes"),
        Just("want"),
        Just("records"),
        Just("genesis"),
        Just("refuse"),
        Just("bogus"),
    ];
    let frame = (
        kinds,
        proptest::collection::btree_map(
            prop_oneof![
                Just("hash".to_owned()),
                Just("count".to_owned()),
                Just("paths".to_owned()),
                Just("nodes".to_owned()),
                Just("ids".to_owned()),
                Just("records".to_owned()),
                Just("done".to_owned()),
                Just("g".to_owned()),
                "[a-z]{1,4}",
            ],
            field(),
            0..5,
        ),
    )
        .prop_map(|(t, fields)| {
            let mut m = cbor::Map::new();
            for (k, v) in fields {
                if k != "t" {
                    m.insert(&k, v);
                }
            }
            m.insert("t", cbor::Value::Text(t.into()));
            cbor::Value::Map(m)
        });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut runner = TestRunner::new(Config {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(48),
        failure_persistence: None,
        ..Config::default()
    });
    let w = world();
    let db = w.genesis.id();
    runner
        .run(&proptest::collection::vec(frame, 1..8), |frames| {
            rt.block_on(async {
                let r = replica(&w);
                let (x, y) = tokio::io::duplex(1 << 20);
                let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
                let (ready_tx, _ready_rx) = oneshot::channel();
                let (store, values) = (r.store.clone(), r.values.clone());
                let session =
                    tokio::spawn(async move { run(x, store, values, db, ev_tx, ready_tx).await });
                let mut peer = RawPeer { stream: y };
                let mut hello = cbor::Map::new();
                hello
                    .insert("t", cbor::Value::Text("hello".into()))
                    .insert("v", cbor::Value::Uint(sameroot_sync::PROTOCOL_VERSION))
                    .insert("nonce", cbor::Value::Bytes(vec![0; 16]))
                    .insert("db", cbor::Value::Bytes(db.0.to_vec()))
                    .insert("needGenesis", cbor::Value::Bool(false))
                    .insert("clock", cbor::Value::Uint(now_ms()));
                peer.send(cbor::Value::Map(hello)).await;
                for f in frames {
                    use tokio::io::AsyncWriteExt;
                    let b = cbor::encode(&f);
                    if peer
                        .stream
                        .write_all(&(b.len() as u32).to_be_bytes())
                        .await
                        .is_err()
                        || peer.stream.write_all(&b).await.is_err()
                    {
                        break; // the session ended on an earlier frame
                    }
                }
                drop(peer);
                match tokio::time::timeout(Duration::from_secs(15), session).await {
                    Ok(Err(e)) if e.is_panic() => Err(TestCaseError::fail("the session panicked")),
                    _ => Ok(()),
                }
            })
        })
        .unwrap();
}
