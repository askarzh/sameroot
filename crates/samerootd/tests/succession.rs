//! End-to-end test of succession in rewrite mode (design 0004 §8): the cut, the
//! nodes following on their own, grants, the read-only parent, collection down to
//! the stub, and a straggler's late write.

mod common;

use common::*;
use sameroot_core::cbor::{Map, Value};
use sameroot_core::succession::{self, Carried, Cut};
use sameroot_core::*;
use sameroot_rpc::{Fields, request};

/// What `sameroot owner succeed --yes` does, through the owner node's RPC.
fn succeed(node: &Daemon, owner: &SecretKey, db: &Digest) -> Digest {
    let mut m = request("succession.cut");
    m.insert("db", Value::Text(db.to_hex()));
    let cut = node.call(m);
    let parent = SignedGenesis::decode(cut.bytes("genesis").unwrap()).unwrap();
    let digest = |b: &[u8]| Digest(b.try_into().unwrap());
    let state: Vec<Carried> = cut
        .list("state")
        .unwrap()
        .iter()
        .map(|v| {
            let Value::Map(m) = v else { panic!() };
            Carried {
                path: Path(
                    m.list("path")
                        .unwrap()
                        .iter()
                        .map(|c| match c {
                            Value::Bytes(b) => b.clone(),
                            _ => panic!(),
                        })
                        .collect(),
                ),
                value_hash: digest(m.bytes("hash").unwrap()),
                value_size: m.uint("size").unwrap(),
                exp: m.uint("exp"),
            }
        })
        .collect();
    let devices: Vec<SignedCert> = cut
        .list("devices")
        .unwrap()
        .iter()
        .map(|v| match v {
            Value::Bytes(b) => SignedCert::decode(b).unwrap(),
            _ => panic!(),
        })
        .collect();
    let plan = succession::rewrite(
        &parent,
        owner,
        &Cut {
            root: digest(cut.bytes("cutRoot").unwrap()),
            count: cut.uint("cutCount").unwrap(),
            as_of: cut.uint("asOf").unwrap(),
        },
        &state,
        &devices,
        None,
        now_ms(),
    )
    .unwrap();
    let mut m = request("db.add");
    m.insert("genesis", Value::Bytes(plan.genesis.encode()));
    let me = node.device();
    if let Some(c) = plan.certs.iter().find(|c| c.cert.subject == me) {
        m.insert("cert", Value::Bytes(c.encode()));
    }
    node.call(m);
    let mut m = request("entries.add");
    m.insert(
        "entries",
        Value::Array(
            plan.entries
                .iter()
                .map(|e| Value::Bytes(e.encode()))
                .collect(),
        ),
    )
    .insert(
        "values",
        Value::Array(plan.values.iter().cloned().map(Value::Bytes).collect()),
    );
    node.call(m);
    let mut m = request("forward.add");
    m.insert("forward", Value::Bytes(plan.forward.encode()));
    node.call(m);
    plan.genesis.id()
}

/// The status of one database on a node.
fn db_status(node: &Daemon, db: &Digest) -> Option<Map> {
    let r = node.try_call(request("status")).ok()?;
    r.list("databases")?.iter().find_map(|d| match d {
        Value::Map(m) if m.text("id") == Some(db.to_hex().as_str()) => Some(m.clone()),
        _ => None,
    })
}

fn has_value(node: &Daemon, value: &[u8]) -> bool {
    let mut m = request("value.has");
    m.insert("hash", Value::Text(value_hash(value).to_hex()));
    node.call(m).flag("has") == Some(true)
}

fn put_in(node: &Daemon, db: &Digest, path: &str, value: &[u8]) -> Map {
    let mut m = request("put");
    m.insert("db", Value::Text(db.to_hex()))
        .insert("exact", Value::Bool(true))
        .insert("path", Value::Text(path.into()))
        .insert("value", Value::Bytes(value.to_vec()));
    node.try_call(m).unwrap()
}

fn add_db(node: &Daemon, g: &SignedGenesis, cert: &SignedCert) {
    let mut m = request("db.add");
    m.insert("genesis", Value::Bytes(g.encode()))
        .insert("cert", Value::Bytes(cert.encode()));
    node.call(m);
}

fn join_exact(node: &Daemon, from: &Daemon, db: &Digest) {
    let mut m = request("invite");
    m.insert("db", Value::Text(db.to_hex()))
        .insert("exact", Value::Bool(true));
    let invite = from.call(m).text("invite").unwrap().to_owned();
    node.join(invite);
}

fn install(node: &Daemon, cert: &SignedCert) {
    let mut m = request("cert.add");
    m.insert("cert", Value::Bytes(cert.encode()));
    node.call(m);
}

#[test]
fn a_database_is_succeeded_followed_and_collected() {
    let owner = SecretKey::from_seed([0x81; 32]);
    let (mut a, mut b, mut c) = (Daemon::new(), Daemon::new(), Daemon::new());
    a.env.push(("SAMEROOT_BLOB_GC_SECS".into(), "1".into()));
    for n in [&mut a, &mut b, &mut c] {
        n.start();
    }
    let g = database(&owner, 1 << 20);
    let parent = g.id();
    add_db(&a, &g, &delegate(&owner, parent, a.device()));
    a.put("notes/keep", b"carried over");
    a.put("notes/old", b"first version");
    a.put("notes/old", b"second version");
    a.put("notes/gone", b"deleted before the cut");
    let mut m = request("del");
    m.insert("path", Value::Text("notes/gone".into()));
    a.call(m);

    let me = owner.public();
    for n in [&b, &c] {
        n.join(a.invite(&parent));
        wait_for(
            "the parent replicates",
            30,
            || n.get(&me, "notes/keep").is_some(),
            &[&a, n],
        );
        install(n, &delegate(&owner, parent, n.device()));
    }
    b.put("notes/b", b"written by B");
    wait_for(
        "A has B's note",
        30,
        || a.get(&me, "notes/b").is_some(),
        &[&a, &b],
    );
    // C writes once (so the owner's node knows its certificate), then goes away
    // before the cut and misses it.
    c.put("notes/c-early", b"written by C");
    wait_for(
        "A has C's note, C has B's",
        30,
        || a.get(&me, "notes/c-early").is_some() && c.get(&me, "notes/b").is_some(),
        &[&a, &c],
    );
    let c_device = c.device();
    c.stop();

    let child = succeed(&a, &owner, &parent);

    // A follows at once; B on its own, with its certificate from the grants.
    for n in [&a, &b] {
        wait_for(
            "the node follows the successor, delegated",
            60,
            || {
                db_status(n, &parent).is_some_and(|d| d.flag("followed") == Some(true))
                    && db_status(n, &child).is_some_and(|d| d.flag("delegated") == Some(true))
            },
            &[&a, &b],
        );
        // Reads go to the successor: the state is there, the deleted key is not.
        assert_eq!(n.get(&me, "notes/keep").unwrap(), b"carried over");
        assert_eq!(n.get(&me, "notes/old").unwrap(), b"second version");
        assert_eq!(n.get(&me, "notes/b").unwrap(), b"written by B");
        assert!(n.get(&me, "notes/gone").is_none());
        // The parent takes no more writes; the grants stay out of listings.
        let r = put_in(n, &parent, "notes/late", b"x");
        assert_eq!(r.flag("ok"), Some(false));
        assert!(r.text("error").unwrap().contains("succeeded"));
        assert!(n.list(false).iter().all(|k| !k.contains(".grants")));
    }
    // Applications seal for the chain's origin: the same for both members.
    for d in [&parent, &child] {
        assert_eq!(
            db_status(&a, d).unwrap().text("origin"),
            Some(parent.to_hex().as_str())
        );
    }

    // A successor's own grants count as its devices for the next succession, even
    // for devices that haven't written there yet; the grants aren't carried as values.
    let mut m = request("succession.cut");
    m.insert("db", Value::Text(child.to_hex()));
    let next = a.call(m);
    let mut subjects: Vec<PublicKey> = next
        .list("devices")
        .unwrap()
        .iter()
        .map(|v| match v {
            Value::Bytes(b) => SignedCert::decode(b).unwrap().cert.subject,
            _ => panic!(),
        })
        .collect();
    subjects.sort();
    let mut want = vec![a.device(), b.device(), c_device];
    want.sort();
    assert_eq!(subjects, want);
    assert!(next.list("state").unwrap().iter().all(|v| match v {
        Value::Map(m) => !matches!(m.list("path").unwrap().first(), Some(Value::Bytes(c)) if c.as_slice() == b".grants"),
        _ => false,
    }));

    // Writes land in the successor and replicate.
    b.put("notes/after", b"after the cut");
    wait_for(
        "A has B's write in the successor",
        30,
        || a.get(&me, "notes/after").is_some(),
        &[&a, &b],
    );

    // Collection: refused in the grace period, then forced.
    let mut m = request("gc");
    m.insert("db", Value::Text(parent.to_hex()));
    assert_eq!(a.try_call(m.clone()).unwrap().flag("ok"), Some(false));
    m.insert("force", Value::Bool(true));
    assert_eq!(a.call(m).uint("removed"), Some(7), "six puts and a delete");
    assert!(db_status(&a, &parent).unwrap().uint("retired").is_some());
    // The overwritten value lived only in the parent; the carried one is shared.
    wait_for(
        "the blob store drops the parent's own values",
        30,
        || !has_value(&a, b"first version"),
        &[&a],
    );
    assert!(has_value(&a, b"second version"));
    assert!(has_value(&a, b"carried over"));
    assert_eq!(a.get(&me, "notes/keep").unwrap(), b"carried over");

    // The straggler wakes up alone and writes to the parent.
    std::fs::remove_file(c.home.join("peers")).unwrap();
    c.start();
    let r = put_in(&c, &parent, "notes/c", b"late from C");
    assert_eq!(r.flag("ok"), Some(true), "{:?}", r.text("error"));
    let late_ts = match r.get("entry") {
        Some(Value::Map(e)) => e.uint("ts").unwrap(),
        _ => panic!("no entry"),
    };
    // Back online: the stub hands it the forward, and it follows on its own.
    join_exact(&c, &a, &parent);
    wait_for(
        "C follows the successor, delegated",
        60,
        || {
            db_status(&c, &parent).is_some_and(|d| d.flag("followed") == Some(true))
                && db_status(&c, &child).is_some_and(|d| d.flag("delegated") == Some(true))
        },
        &[&a, &c],
    );
    assert_eq!(db_status(&c, &parent).unwrap().uint("late"), Some(1));
    let late = c.call(request("late"));
    let entries = late.list("entries").unwrap();
    assert_eq!(entries.len(), 1);
    let r = c.call(request("late.resubmit"));
    assert_eq!(r.uint("written"), Some(1));
    assert_eq!(db_status(&c, &parent).unwrap().uint("late"), Some(0));
    wait_for(
        "A has C's late write in the successor",
        30,
        || a.get(&me, "notes/c").is_some(),
        &[&a, &c],
    );
    assert_eq!(a.get(&me, "notes/c").unwrap(), b"late from C");
    let mut m = request("get");
    m.insert("path", Value::Text("notes/c".into()))
        .insert("subspace", Value::Text(me.to_hex()));
    let resubmitted = match a.call(m).get("entry") {
        Some(Value::Map(e)) => e.uint("ts").unwrap(),
        _ => panic!("no entry"),
    };
    assert_eq!(
        resubmitted, late_ts,
        "a resubmitted late write keeps its time"
    );
}
