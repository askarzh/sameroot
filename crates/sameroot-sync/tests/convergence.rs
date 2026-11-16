//! Convergence (design 0003 §10.1–10.2): three replicas, random delivery subsets
//! and orders, sessions over in-process streams. Every replica must end with the
//! ledger root of the delivered set and with the state that resolution computes
//! directly from it; the replica that started empty must also get the values.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sameroot_core::ledger::{Kind, Trie};
use sameroot_core::resolve::{LedgerEntry, LedgerVoid, Resolved, State, resolve};
use sameroot_core::*;
use sameroot_store::Store;
use sameroot_sync::{Event, MemValues, Session};
use tokio::sync::{mpsc, oneshot};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

enum Op1 {
    Entry(SignedEntry, Option<Vec<u8>>),
    /// A void and, when it has `keep`, its keep list.
    Void(SignedVoid, Option<Vec<Digest>>),
}

struct Scenario {
    genesis: SignedGenesis,
    cert: SignedCert,
    owner_a: PublicKey,
    ops: Vec<Op1>,
}

fn scenario(seed: u64) -> Scenario {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let owner_a = SecretKey::from_seed([0xa1; 32]);
    let device_a = SecretKey::from_seed([0xd1; 32]);
    let owner_b = SecretKey::from_seed([0xb1; 32]);
    let base = now_ms() - 60_000;
    let mut g = Genesis::new(
        "conv",
        owner_a.public(),
        logic::presets::own_subspace(),
        base,
    );
    g.nonce = [seed as u8; 16];
    let db = g.id();
    let genesis = g.sign(&owner_a);
    let cert = Cert {
        issuer: owner_a.public(),
        subject: device_a.public(),
        parent: None,
        db,
        area: Area {
            subspace: Subspace::Owner(owner_a.public()),
            path_prefix: Path::default(),
            ops: vec![Op::Put, Op::Delete, Op::Negate],
        },
        not_before: base - 1,
        not_after: base + 3_600_000,
        name: Some("laptop".into()),
        endpoint: None,
    }
    .sign(&owner_a);
    let mut ops = Vec::new();
    let mut entries: Vec<Digest> = Vec::new();
    for n in 0..40 {
        let (signer, subspace, via_cert) = match rng.below(3) {
            0 => (&owner_a, owner_a.public(), None),
            1 => (&device_a, owner_a.public(), Some(cert.id())),
            _ => (&owner_b, owner_b.public(), None),
        };
        let key = format!("k{}", rng.below(5)); // few keys: many conflicts
        let ts = base + rng.below(20); // few timestamps: ties broken by entry id
        let kind = rng.below(6);
        let value = format!("v{n}").into_bytes();
        let (op, target) = match kind {
            0 => (Op::Delete, None),
            1 if !entries.is_empty() => (
                Op::Negate,
                Some(entries[rng.below(entries.len() as u64) as usize]),
            ),
            _ => (Op::Put, None),
        };
        let put = op == Op::Put;
        let header = Header {
            db,
            subspace: Subspace::Owner(subspace),
            path: Path::parse(&key).unwrap(),
            op,
            ts,
            exp: None,
            value_size: if put { value.len() as u64 } else { 0 },
            value_hash: if put {
                value_hash(&value)
            } else {
                Digest::ZERO
            },
            target,
            signer: signer.public(),
            cert: via_cert,
            work: 0,
        };
        let e = header.sign(signer);
        entries.push(e.id());
        ops.push(Op1::Entry(e, put.then_some(value)));
    }
    if rng.below(3) != 0 {
        // Total, or keeping a random subset of the device's entries (design 0004 §5).
        let total = Void::of_cert(db, cert.id(), owner_a.public());
        if rng.below(2) == 0 {
            ops.push(Op1::Void(total.sign(&owner_a), None));
        } else {
            let mut kept: Vec<Digest> = ops
                .iter()
                .filter_map(|o| match o {
                    Op1::Entry(e, _) if e.header.cert.is_some() && rng.below(2) == 0 => {
                        Some(e.id())
                    }
                    _ => None,
                })
                .collect();
            kept.sort();
            let keep = Keep {
                root: Trie::build(kept.iter().map(|d| (Kind::Entry, *d))).root(),
                count: kept.len() as u64,
            };
            let before = (rng.below(2) == 0).then(|| base + 10);
            let v = Void {
                keep: Some(keep),
                before,
                ..total
            };
            ops.push(Op1::Void(v.sign(&owner_a), Some(kept)));
        }
    }
    Scenario {
        genesis,
        cert,
        owner_a: owner_a.public(),
        ops,
    }
}

/// The expected ledger root and state, computed directly from the delivered set.
fn expected(s: &Scenario, delivered: &[bool], as_of: u64) -> (Digest, State) {
    let mut records = Vec::new();
    let mut entries = Vec::new();
    let mut voids = Vec::new();
    for (op, _) in s.ops.iter().zip(delivered).filter(|(_, d)| **d) {
        match op {
            Op1::Entry(e, _) => {
                records.push((Kind::Entry, e.id()));
                let via_cert = e.header.cert.is_some();
                entries.push(LedgerEntry {
                    id: e.id(),
                    header: e.header.clone(),
                    chain_root: if via_cert { s.owner_a } else { e.header.signer },
                    chain: e.header.cert.into_iter().collect(),
                });
            }
            Op1::Void(v, keep) => {
                records.push((Kind::Void, v.id()));
                voids.push(LedgerVoid {
                    keep: keep.as_ref().map(|k| k.iter().copied().collect()),
                    before: v.void.before,
                    ..LedgerVoid::total(v.id(), s.cert.id())
                });
            }
        }
    }
    let g = &s.genesis.genesis;
    (
        Trie::build(records).root(),
        resolve(&entries, &voids, &g.contract.resolution, &g.owner, as_of),
    )
}

/// The state by a second, deliberately naive reading of the rules (design 0003
/// §5.3, design 0004 §5.3), written without `resolve`, so a mistake shared by the
/// implementation and its own expectation can't pass unnoticed.
///
/// - An entry is dead if a delivered void of its certificate covers it (no `before`,
///   or `ts < before`) and doesn't keep it.
/// - Negations target earlier ops only, so walking the ops backwards decides every
///   negation before its target: an op is negated if a later live, un-negated
///   negation by the same author (chain root) targets it.
/// - Per key, the live, un-negated put or delete with the largest `(ts, id)` wins.
fn oracle(s: &Scenario, delivered: &[bool]) -> State {
    let ops: Vec<(&SignedEntry, usize)> = s
        .ops
        .iter()
        .enumerate()
        .filter(|(i, _)| delivered[*i])
        .filter_map(|(i, o)| match o {
            Op1::Entry(e, _) => Some((e, i)),
            Op1::Void(..) => None,
        })
        .collect();
    let voids: Vec<(&SignedVoid, Option<&Vec<Digest>>)> = s
        .ops
        .iter()
        .enumerate()
        .filter(|(i, _)| delivered[*i])
        .filter_map(|(_, o)| match o {
            Op1::Void(v, k) => Some((v, k.as_ref())),
            Op1::Entry(..) => None,
        })
        .collect();
    let root = |e: &SignedEntry| {
        if e.header.cert.is_some() {
            s.owner_a
        } else {
            e.header.signer
        }
    };
    let dead = |e: &SignedEntry| {
        e.header.cert == Some(s.cert.id())
            && voids.iter().any(|(v, keep)| {
                let covers = v.void.before.is_none_or(|b| e.header.ts < b);
                covers && !keep.is_some_and(|k| k.contains(&e.id()))
            })
    };
    let mut negated: HashMap<Digest, bool> = HashMap::new();
    for (e, i) in ops.iter().rev() {
        let by_later = ops.iter().any(|(n, j)| {
            j > i
                && n.header.op == Op::Negate
                && n.header.target == Some(e.id())
                && !dead(n)
                && !negated[&n.id()]
                && root(n) == root(e)
        });
        negated.insert(e.id(), by_later);
    }
    let mut state = State::new();
    let mut best: HashMap<(Subspace, Path), (u64, Digest, Op)> = HashMap::new();
    for (e, _) in &ops {
        let h = &e.header;
        if h.op == Op::Negate || dead(e) || negated[&e.id()] {
            continue;
        }
        let k = (h.subspace, h.path.clone());
        let cand = (h.ts, e.id(), h.op);
        if best.get(&k).is_none_or(|b| (b.0, b.1) < (cand.0, cand.1)) {
            best.insert(k, cand);
        }
    }
    for (k, (_, id, op)) in best {
        state.insert(
            k,
            if op == Op::Put {
                Resolved::Value(id)
            } else {
                Resolved::Deleted(id)
            },
        );
    }
    state
}

/// Connects two replicas and forwards session events, so a replica that learns
/// something from one session announces its new root on all its others (the node's
/// fan-out). A value reported missing is copied from any replica that holds it, as
/// the node fetches it from a peer's blob store.
async fn connect(
    a: usize,
    b: usize,
    stores: &[Arc<Mutex<Store>>],
    values: &[MemValues],
    sessions: &Arc<Mutex<HashMap<usize, Vec<Session>>>>,
    db: Digest,
) {
    let (x, y) = tokio::io::duplex(1 << 20);
    for (stream, r) in [(x, a), (y, b)] {
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (store, own) = (stores[r].clone(), values[r].clone());
        tokio::spawn(async move {
            let _ = sameroot_sync::run(stream, store, own, db, ev_tx, ready_tx).await;
        });
        let session = ready_rx.await.unwrap();
        sessions.lock().unwrap().entry(r).or_default().push(session);
        let sessions = sessions.clone();
        let values = values.to_vec();
        tokio::spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                match ev {
                    Event::Added { .. } | Event::Joined(_) => {
                        for s in sessions.lock().unwrap().get(&r).into_iter().flatten() {
                            s.resync();
                        }
                    }
                    Event::MissingValue { hash, .. } => {
                        if let Some(v) = values.iter().find_map(|x| x.value(&hash)) {
                            values[r].insert(&v);
                        }
                    }
                    Event::InSync(_) => {}
                }
            }
        });
    }
}

async fn run_seed(seed: u64) {
    let s = scenario(seed);
    let db = s.genesis.id();
    let mut rng = Rng(seed ^ 0xdead_beef);
    let stores: Vec<Arc<Mutex<Store>>> = (0..3)
        .map(|_| Arc::new(Mutex::new(Store::in_memory().unwrap())))
        .collect();
    let values: Vec<MemValues> = (0..3).map(|_| MemValues::new()).collect();
    // Replicas 0 and 1 know the database and receive the operations in random
    // subsets and orders; replica 2 starts empty, without even the genesis.
    let now = now_ms();
    let mut order: Vec<usize> = (0..s.ops.len()).collect();
    let mut delivered = vec![false; s.ops.len()];
    for (r, vals) in stores[..2].iter().zip(&values) {
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let st = r.lock().unwrap();
        st.add_database(&s.genesis).unwrap();
        for &i in &order {
            if rng.below(2) == 0 {
                let ok = match &s.ops[i] {
                    Op1::Entry(e, v) => {
                        let r = st.insert_entry(e, std::slice::from_ref(&s.cert), now);
                        if let Some(v) = v {
                            vals.insert(v);
                        }
                        r.is_ok()
                    }
                    Op1::Void(v, keep) => st
                        .insert_void(v, std::slice::from_ref(&s.cert), keep.as_deref())
                        .is_ok(),
                };
                // Everything in the scenario is admissible (negations by the wrong
                // author are admitted and only lose their effect).
                assert!(ok, "seed {seed}: op {i} admitted");
                delivered[i] = true;
            }
        }
    }
    // Sessions in a random order, with pauses: a partition that heals.
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let mut pairs = [(0, 1), (1, 2), (0, 2)];
    for i in (1..pairs.len()).rev() {
        pairs.swap(i, rng.below(i as u64 + 1) as usize);
    }
    for (a, b) in pairs {
        connect(a, b, &stores, &values, &sessions, db).await;
        tokio::time::sleep(Duration::from_millis(rng.below(30))).await;
    }
    let (want_root, want_state) = expected(&s, &delivered, now);
    assert_eq!(
        want_state,
        oracle(&s, &delivered),
        "seed {seed}: resolve disagrees with the naive reading of the rules"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let roots: Vec<Option<Digest>> = stores
            .iter()
            .map(|r| r.lock().unwrap().root(&db).ok().map(|(_, h)| h))
            .collect();
        if roots.iter().all(|r| *r == Some(want_root)) {
            for (i, r) in stores.iter().enumerate() {
                let st = r.lock().unwrap();
                assert_eq!(
                    st.state(&db, now).unwrap(),
                    want_state,
                    "seed {seed}: replica {i} state"
                );
            }
            // The replica that started empty also holds every winning value.
            let wanted_values: Vec<Digest> = want_state
                .values()
                .filter_map(|r| match r {
                    Resolved::Value(id) => Some(*id),
                    _ => None,
                })
                .map(|id| {
                    stores[0]
                        .lock()
                        .unwrap()
                        .entry(&db, &id)
                        .unwrap()
                        .unwrap()
                        .header
                        .value_hash
                })
                .collect();
            loop {
                let have = wanted_values.iter().all(|h| values[2].contains(h));
                if have {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "seed {seed}: values didn't arrive"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "seed {seed}: no convergence; roots {roots:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_replicas_converge_to_the_ledger_and_its_state() {
    for seed in 1..=25 {
        run_seed(seed).await;
    }
}
