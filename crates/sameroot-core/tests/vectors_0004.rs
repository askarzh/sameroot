//! Conformance vectors for the design 0004 additions (`vectors/0004.json`).
//!
//! Like `vectors/core.json`, they were generated once by this implementation (run
//! with `SAMEROOT_WRITE_VECTORS=1` to create the file when it doesn't exist) and are
//! checked in. This test only compares; a mismatch means the format changed.

use std::path::PathBuf;

use sameroot_core::cbor;
use sameroot_core::hash::hex;
use sameroot_core::ledger::{Kind, Trie};
use sameroot_core::refs::{RefIndex, RefTag, ledger_commitment, ref_key};
use sameroot_core::*;
use serde_json::{Value as Json, json};

struct Fixture {
    owner: SecretKey,
    device: SecretKey,
    genesis: Genesis,
    db: Digest,
    cert: SignedCert,
    puts: Vec<SignedEntry>,
}

fn fixture() -> Fixture {
    let owner = SecretKey::from_seed([0x51; 32]);
    let device = SecretKey::from_seed([0x52; 32]);
    let mut genesis = Genesis::new(
        "vectors 0004",
        owner.public(),
        logic::presets::own_subspace(),
        1_760_000_000_000,
    );
    genesis.nonce = [0x53; 16];
    genesis.limits.max_keep_count = Some(1_000);
    genesis.limits.void_work = Some(4);
    genesis.next_owner = Some(owner_commitment(&SecretKey::from_seed([0x54; 32]).public()));
    genesis.predecessor = Some(Predecessor {
        db: Digest([0x55; 32]),
        cut_root: Digest([0x56; 32]),
        cut_count: 42,
        as_of: 1_759_999_000_000,
        carry_root: None,
    });
    let db = genesis.id();
    let cert = Cert {
        issuer: owner.public(),
        subject: device.public(),
        parent: None,
        db,
        area: Area {
            subspace: Subspace::Owner(owner.public()),
            path_prefix: Path::default(),
            ops: vec![Op::Put, Op::Delete, Op::Negate],
        },
        not_before: 1_760_000_000_000,
        not_after: 1_790_000_000_000,
        name: Some("laptop".into()),
        endpoint: Some(PublicKey([0x57; 32])),
    }
    .sign(&owner);
    let puts = (0..3u64)
        .map(|i| {
            let value = format!("value {i}").into_bytes();
            Header {
                db,
                subspace: Subspace::Owner(owner.public()),
                path: Path::from_strs(["notes", &format!("{i}")]),
                op: Op::Put,
                ts: 1_760_000_001_000 + i,
                exp: None,
                value_size: value.len() as u64,
                value_hash: value_hash(&value),
                target: None,
                signer: device.public(),
                cert: Some(cert.id()),
                work: 0,
            }
            .sign(&device)
        })
        .collect();
    Fixture {
        owner,
        device,
        genesis,
        db,
        cert,
        puts,
    }
}

fn compute() -> Json {
    let f = fixture();
    let signed_genesis = f.genesis.clone().sign(&f.owner);

    let mut mined = f.puts[0].header.clone();
    mined.path = Path::from_strs(["mined"]);
    mined.mine(12);
    let mined = mined.sign(&f.device);

    let mut kept: Vec<Digest> = vec![f.puts[0].id(), f.puts[2].id()];
    kept.sort();
    let keep_root = Trie::build(kept.iter().map(|d| (Kind::Entry, *d))).root();
    let keep_void = Void {
        keep: Some(Keep {
            root: keep_root,
            count: kept.len() as u64,
        }),
        before: Some(1_790_000_000_000),
        ..Void::of_cert(f.db, f.cert.id(), f.owner.public())
    }
    .sign(&f.owner);

    let mut kill = Void::of_key(f.db, f.device.public());
    kill.mine(4);
    let kill = kill.sign(&f.device);

    let forward = Forward {
        db: f.db,
        successor: Digest([0x58; 32]),
        owner: SecretKey::from_seed([0x54; 32]).public(),
        cut_root: Digest([0x59; 32]),
    }
    .sign(&f.owner);

    let negation = Header {
        db: f.db,
        subspace: Subspace::Owner(f.owner.public()),
        path: Path::from_strs(["notes", "1"]),
        op: Op::Negate,
        ts: 1_760_000_002_000,
        exp: None,
        value_size: 0,
        value_hash: Digest::ZERO,
        target: Some(f.puts[1].id()),
        signer: f.owner.public(),
        cert: None,
        work: 0,
    }
    .sign(&f.owner);

    // The ledger of all of the above, and its commitment.
    let mut records: Vec<(Kind, Digest)> = f.puts.iter().map(|e| (Kind::Entry, e.id())).collect();
    records.extend([
        (Kind::Entry, mined.id()),
        (Kind::Entry, negation.id()),
        (Kind::Void, keep_void.id()),
        (Kind::Void, kill.id()),
        (Kind::Forward, forward.id()),
    ]);
    let record_root = Trie::build(records.iter().copied()).root();
    let mut refs = RefIndex::new();
    refs.insert(
        ref_key(RefTag::Cert, &f.cert.id().0),
        Kind::Void,
        keep_void.id(),
    );
    refs.insert(
        ref_key(RefTag::Key, &f.device.public().0),
        Kind::Void,
        kill.id(),
    );
    refs.insert(
        ref_key(RefTag::Target, &f.puts[1].id().0),
        Kind::Entry,
        negation.id(),
    );
    let ref_root = refs.root();

    json!({
        "description": "Sameroot design 0004 conformance vectors (format 1 additions). Keys are Ed25519 seeds; binary values are lowercase hex.",
        "keys": { "ownerSeed": hex(&f.owner.seed()), "deviceSeed": hex(&f.device.seed()),
                  "nextOwnerSeed": hex(&[0x54; 32]) },
        "genesis": { "canonical": hex(&cbor::encode(&f.genesis.to_value())), "id": f.db.to_hex(),
                     "signed": hex(&signed_genesis.encode()),
                     "nextOwnerCommitment": owner_commitment(&SecretKey::from_seed([0x54; 32]).public()).to_hex() },
        "certWithEndpoint": { "canonical": hex(&cbor::encode(&f.cert.cert.to_value())), "id": f.cert.id().to_hex(),
                              "signed": hex(&f.cert.encode()) },
        "puts": f.puts.iter().map(|e| json!({ "id": e.id().to_hex(), "signed": hex(&e.encode()) })).collect::<Vec<_>>(),
        "headerWithWork": { "header": hex(&mined.header.encode()), "id": mined.id().to_hex(),
                            "work": mined.header.work, "workBits": work_bits(&mined.id()),
                            "signed": hex(&mined.encode()) },
        "voidWithKeep": { "canonical": hex(&cbor::encode(&keep_void.void.to_value())), "id": keep_void.id().to_hex(),
                          "signed": hex(&keep_void.encode()),
                          "keepList": kept.iter().map(|d| d.to_hex()).collect::<Vec<_>>(),
                          "keepRoot": keep_root.to_hex() },
        "keyVoid": { "canonical": hex(&cbor::encode(&kill.void.to_value())), "id": kill.id().to_hex(),
                     "signed": hex(&kill.encode()), "workBits": work_bits(&kill.id()) },
        "forward": { "canonical": hex(&cbor::encode(&forward.forward.to_value())), "id": forward.id().to_hex(),
                     "signed": hex(&forward.encode()) },
        "negation": { "id": negation.id().to_hex(), "signed": hex(&negation.encode()) },
        "ledger": { "recordRoot": record_root.to_hex(), "refRoot": ref_root.to_hex(),
                    "ledgerRoot": ledger_commitment(&record_root, &ref_root).to_hex(),
                    "emptyRefRoot": RefIndex::new().root().to_hex() },
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/0004.json")
}

#[test]
fn vectors_0004_match() {
    let computed = compute();
    let file = path();
    if !file.exists() {
        assert!(
            std::env::var("SAMEROOT_WRITE_VECTORS").is_ok(),
            "vectors/0004.json is missing; generate it once with SAMEROOT_WRITE_VECTORS=1"
        );
        std::fs::write(
            &file,
            serde_json::to_string_pretty(&computed).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Json = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        stored, computed,
        "format 1 output differs from vectors/0004.json"
    );
}

/// The stored records decode and pass admission against the stored genesis.
#[test]
fn vectors_0004_verify() {
    let stored: Json = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    let unhex = |v: &Json| hash::unhex(v.as_str().unwrap()).unwrap();
    let genesis = SignedGenesis::decode(&unhex(&stored["genesis"]["signed"])).unwrap();
    let db = genesis.id();
    let g = &genesis.genesis;
    let cert = SignedCert::decode(&unhex(&stored["certWithEndpoint"]["signed"])).unwrap();
    let lookup = |id: &Digest| (*id == cert.id()).then(|| cert.clone());

    let void = SignedVoid::decode(&unhex(&stored["voidWithKeep"]["signed"])).unwrap();
    let keep: Vec<Digest> = stored["voidWithKeep"]["keepList"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Digest::from_hex(v.as_str().unwrap()).unwrap())
        .collect();
    let accepted = verify_void(g, &db, &void, &lookup, Some(&keep)).unwrap();
    assert_eq!(
        accepted.id.to_hex(),
        stored["voidWithKeep"]["id"].as_str().unwrap()
    );
    assert_eq!(
        verify_void(g, &db, &void, &lookup, None),
        Err(Reject::KeepMissing)
    );

    let kill = SignedVoid::decode(&unhex(&stored["keyVoid"]["signed"])).unwrap();
    assert!(
        verify_void(g, &db, &kill, &lookup, None).is_ok(),
        "mined to voidWork"
    );

    let forward = SignedForward::decode(&unhex(&stored["forward"]["signed"])).unwrap();
    assert_eq!(
        verify_forward(g, &db, &forward).unwrap().to_hex(),
        stored["forward"]["id"].as_str().unwrap()
    );

    let mined = SignedEntry::decode(&unhex(&stored["headerWithWork"]["signed"])).unwrap();
    assert!(mined.header.work > 0);
    assert!(work_bits(&mined.id()) >= 12);
    assert!(verify_entry(g, &db, &mined, &lookup).is_ok());
}
