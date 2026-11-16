//! Known-answer vectors for sealed values and hidden names (`vectors/seal.json`).
//!
//! Memory written today must stay readable: a change to a context string, to the
//! token encoding or to the sealed layout would silently make every stored value
//! and every hidden name unreadable. The vectors were generated once (run with
//! `SAMEROOT_WRITE_VECTORS=1` to create the file when it doesn't exist) and are
//! checked in; this test only compares.

use std::path::PathBuf;

use sameroot_seal::{MemoryKey, is_hidden_path, is_sealed, sealed_key_id};
use serde_json::{Value as Json, json};

const KEY: [u8; 32] = [0x71; 32];
const DB: [u8; 32] = [0x72; 32];
const PATHS: &[&str] = &["notes/topic", "projects/apollo/plan", "a"];
const PLAINTEXT: &[u8] = b"{\"$sameroot\":1,\"key\":\"notes/topic\",\"value\":\"remember this\"}";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/seal.json")
}

#[test]
fn seal_vectors_match() {
    let key = MemoryKey::from_bytes(&KEY).unwrap();
    let hidden: serde_json::Map<String, Json> = PATHS
        .iter()
        .map(|p| (p.to_string(), json!(key.hide_path(p))))
        .collect();
    let file = path();
    if !file.exists() {
        assert!(
            std::env::var("SAMEROOT_WRITE_VECTORS").is_ok(),
            "vectors/seal.json is missing; generate it once with SAMEROOT_WRITE_VECTORS=1"
        );
        let v = json!({
            "description": "sameroot-seal known answers: the memory key is the 32-byte key below; the sealed value was made once with a random nonce and must keep opening.",
            "key": hex(&KEY),
            "keyId": key.id_hex(),
            "hiddenPaths": hidden,
            "db": hex(&DB),
            "path": PATHS[0],
            "plaintext": String::from_utf8(PLAINTEXT.to_vec()).unwrap(),
            "sealed": hex(&key.seal(&DB, PATHS[0], PLAINTEXT)),
        });
        std::fs::write(&file, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    let stored: Json = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(stored["keyId"], json!(key.id_hex()), "key id");
    assert_eq!(stored["hiddenPaths"], Json::Object(hidden), "hidden names");
    let sealed = unhex(stored["sealed"].as_str().unwrap());
    assert!(is_sealed(&sealed));
    assert_eq!(sealed_key_id(&sealed), Some(key.id_hex()));
    assert_eq!(
        key.open(&DB, PATHS[0], &sealed).unwrap(),
        PLAINTEXT,
        "a stored value still opens"
    );
    // Bound to its database and path.
    assert!(key.open(&DB, PATHS[1], &sealed).is_err());
    assert!(key.open(&[0; 32], PATHS[0], &sealed).is_err());
    for p in stored["hiddenPaths"].as_object().unwrap().values() {
        assert!(is_hidden_path(p.as_str().unwrap()));
    }
}

/// Inputs around the header length are refused without a panic.
#[test]
fn short_inputs_are_refused() {
    let key = MemoryKey::from_bytes(&KEY).unwrap();
    let sealed = key.seal(&DB, "a", b"x");
    for n in 0..sealed.len() {
        let cut = &sealed[..n];
        assert!(key.open(&DB, "a", cut).is_err(), "{n} bytes");
    }
    assert!(!is_sealed(b"SRS1"));
}
