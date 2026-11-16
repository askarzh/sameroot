//! Conformance vectors (`vectors/core.json`).
//!
//! The vectors were generated once by this implementation (run with
//! `SAMEROOT_WRITE_VECTORS=1` to create the file when it doesn't exist) and are
//! checked in. This test only compares: a mismatch means the format changed, and the
//! fix is in the code, never in the vectors.

use std::path::PathBuf;

use sameroot_core::cbor;
use sameroot_core::hash::hex;
use sameroot_core::*;
use serde_json::{Value as Json, json};

fn compute() -> Json {
    let owner = SecretKey::from_seed([0x11; 32]);
    let device = SecretKey::from_seed([0x22; 32]);

    let mut genesis = Genesis::new(
        "vectors",
        owner.public(),
        logic::presets::own_subspace(),
        1_700_000_000_000,
    );
    genesis.nonce = [0x33; 16];
    let db = genesis.id();
    let signed_genesis = genesis.clone().sign(&owner);

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
        not_before: 1_700_000_000_000,
        not_after: 1_800_000_000_000,
        name: Some("laptop".into()),
        endpoint: None,
    }
    .sign(&owner);

    let value = b"hello, sameroot";
    let put = Header {
        db,
        subspace: Subspace::Owner(owner.public()),
        path: Path::from_strs(["notes", "greeting"]),
        op: Op::Put,
        ts: 1_700_000_000_123,
        exp: None,
        value_size: value.len() as u64,
        value_hash: value_hash(value),
        target: None,
        signer: device.public(),
        cert: Some(cert.id()),
        work: 0,
    }
    .sign(&device);
    let delete = Header {
        db,
        subspace: Subspace::Owner(owner.public()),
        path: Path::from_strs(["notes", "greeting"]),
        op: Op::Delete,
        ts: 1_700_000_000_456,
        exp: None,
        value_size: 0,
        value_hash: Digest::ZERO,
        target: None,
        signer: owner.public(),
        cert: None,
        work: 0,
    }
    .sign(&owner);
    let negate = Header {
        db,
        subspace: Subspace::Owner(owner.public()),
        path: Path::from_strs(["notes", "greeting"]),
        op: Op::Negate,
        ts: 1_700_000_000_789,
        exp: None,
        value_size: 0,
        value_hash: Digest::ZERO,
        target: Some(put.id()),
        signer: device.public(),
        cert: Some(cert.id()),
        work: 0,
    }
    .sign(&device);
    let void = Void::of_cert(db, cert.id(), owner.public()).sign(&owner);
    let k = PublicKey([0x44; 32]);
    let presets = json!({
        "always": hex(&cbor::encode(&logic::presets::always())),
        "ownSubspace": hex(&cbor::encode(&logic::presets::own_subspace())),
        "ownerOnly": hex(&cbor::encode(&logic::presets::owner_only())),
        "allowlist44": hex(&cbor::encode(&logic::presets::allowlist(&[k]))),
        "sharedAllowlist44": hex(&cbor::encode(&logic::presets::shared_allowlist(&[k]))),
        "publicShared": hex(&cbor::encode(&logic::presets::public_shared())),
        "putOnlyOwnSubspace": hex(&cbor::encode(&logic::presets::put_only(logic::presets::own_subspace()))),
        "namespacePerWriter": hex(&cbor::encode(&logic::presets::namespace_per_writer())),
    });

    let rejects = [
        ("tag", "c100", "unsupported"),
        ("half float", "f93c00", "unsupported"),
        ("indefinite array", "9f00ff", "indefinite"),
        ("integer key", "a10000", "non-text key"),
        ("keys out of order", "a2616201616101", "key order"),
        ("duplicate key", "a2616101616101", "key order"),
        ("trailing bytes", "0000", "trailing bytes"),
        ("non-shortest integer", "1817", "non-canonical integer"),
        ("non-shortest length", "5a00000010", "non-canonical integer"),
        ("invalid UTF-8", "62c328", "invalid utf-8"),
    ];

    json!({
        "description": "Sameroot format 1 conformance vectors. Keys are Ed25519 seeds; binary values are lowercase hex.",
        "keys": { "ownerSeed": hex(&owner.seed()), "ownerPublic": owner.public().to_hex(),
                  "deviceSeed": hex(&device.seed()), "devicePublic": device.public().to_hex() },
        "genesis": { "nonce": hex(&genesis.nonce), "createdAt": genesis.created_at,
                     "canonical": hex(&cbor::encode(&genesis.to_value())), "id": db.to_hex(),
                     "signed": hex(&signed_genesis.encode()) },
        "cert": { "canonical": hex(&cbor::encode(&cert.cert.to_value())), "id": cert.id().to_hex(),
                  "signed": hex(&cert.encode()) },
        "value": { "bytes": hex(value), "hash": value_hash(value).to_hex() },
        "putByDevice": { "header": hex(&put.header.encode()), "id": put.id().to_hex(),
                         "signature": hex(&put.sig.0), "signed": hex(&put.encode()) },
        "deleteByOwner": { "header": hex(&delete.header.encode()), "id": delete.id().to_hex(),
                           "signature": hex(&delete.sig.0), "signed": hex(&delete.encode()),
                           "winsOverPut": wins(&delete.header, &put.header) },
        "negateByDevice": { "header": hex(&negate.header.encode()), "id": negate.id().to_hex(),
                            "signed": hex(&negate.encode()) },
        "voidByOwner": { "canonical": hex(&cbor::encode(&void.void.to_value())), "id": void.id().to_hex(),
                         "signed": hex(&void.encode()) },
        "presets": presets,
        "cborRejects": rejects.iter().map(|(name, input, reason)| json!({ "case": name, "input": input, "reason": reason })).collect::<Vec<_>>(),
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/core.json")
}

#[test]
fn core_vectors_match() {
    let computed = compute();
    let file = path();
    if !file.exists() {
        assert!(
            std::env::var("SAMEROOT_WRITE_VECTORS").is_ok(),
            "vectors/core.json is missing; generate it once with SAMEROOT_WRITE_VECTORS=1"
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
        "format 1 output differs from vectors/core.json"
    );
}

#[test]
fn vectors_verify_and_rejects_reject() {
    let stored: Json = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    let unhex = |v: &Json| hash::unhex(v.as_str().unwrap()).unwrap();

    let genesis = SignedGenesis::decode(&unhex(&stored["genesis"]["signed"]))
        .expect("genesis decodes and verifies");
    let db = genesis.id();
    assert_eq!(db.to_hex(), stored["genesis"]["id"].as_str().unwrap());
    let cert = SignedCert::decode(&unhex(&stored["cert"]["signed"])).unwrap();
    let lookup = |id: &Digest| (*id == cert.id()).then(|| cert.clone());

    let void = SignedVoid::decode(&unhex(&stored["voidByOwner"]["signed"])).unwrap();
    assert_eq!(
        verify_void(&genesis.genesis, &db, &void, &lookup, None)
            .unwrap()
            .id
            .to_hex(),
        stored["voidByOwner"]["id"].as_str().unwrap()
    );
    for case in ["putByDevice", "deleteByOwner", "negateByDevice"] {
        let entry = SignedEntry::decode(&unhex(&stored[case]["signed"])).unwrap();
        assert_eq!(entry.id().to_hex(), stored[case]["id"].as_str().unwrap());
        verify_entry(&genesis.genesis, &db, &entry, &lookup)
            .unwrap_or_else(|e| panic!("{case}: {e}"));
    }
    for case in stored["cborRejects"].as_array().unwrap() {
        assert!(
            cbor::decode(&unhex(&case["input"])).is_err(),
            "{}",
            case["case"]
        );
    }
}
